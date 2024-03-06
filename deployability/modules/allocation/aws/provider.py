import boto3
import fnmatch
import os
import re
import sys
from pathlib import Path

from modules.allocation.generic import Provider
from modules.allocation.generic.models import CreationPayload
from modules.allocation.generic.utils import logger
from .credentials import AWSCredentials
from .instance import AWSInstance
from .models import AWSConfig


class AWSProvider(Provider):
    """
    AWSProvider class for managing AWS EC2 instances.
    It inherits from the generic Provider class.

    Attributes:
        provider_name (str): Name of the provider ('aws').
    """

    provider_name = 'aws'

    @classmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload, config: AWSConfig = None, ssh_key: str = None) -> AWSInstance:
        """
        Create an AWS EC2 instance.

        Args:
            base_dir (Path): Base directory for storing instance data.
            params (CreationPayload): Payload containing creation parameters.
            config (AWSConfig, optional): Configuration for the instance. Defaults to None.
            ssh_key (str, optional): Public or private key for the instance. For example, we assume that if the public key is provided, the private key is located in the same directory and has the same name as the public key. Defaults to None.

        Returns:
            AWSInstance: Created AWSInstance object.
        """
        temp_id = cls._generate_instance_id(cls.provider_name)
        temp_dir = base_dir / temp_id
        credentials = AWSCredentials()
        teams = ['qa', 'core', 'framework', 'devops', 'frontend', 'operations', 'cloud', 'threat-intel', 'marketing', 'documentation']
        platform = str(params.composite_name.split("-")[0])
        arch = str(params.composite_name.split("-")[3])
        if not config:
            logger.debug(f"No config provided. Generating from payload")
            # Labels
            issue = params.label_issue
            label_team = params.label_team
            termination_date = params.label_termination_date
            host_identifier = None
            date_regex = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
            url_regex = "(https:\/\/|http:\/\/)?[github]{2,}(\.[com]{2,})?\/wazuh\/[a-zA-Z0-9_-]+(?:-[a-zA-Z0-9_-]+)?\/issues\/[0-9]{2,}"
            if not termination_date or not re.match(date_regex, termination_date):
                logger.error(f"The termination_date label was not provided or is of incorrect format, example: 2024-02-25 12:00:00.")
                sys.exit(1)
            if label_team:
                not_match = 0
                for team in teams:
                    if label_team == team:
                        label_team = team
                        break
                    else:
                        not_match += 1
                if not_match == len(teams):
                    logger.error(f"The team label provided does not match any of the available teams.")
                    sys.exit(1)
            else:
                logger.error(f"The team label was not provided.")
                sys.exit(1)
            if not issue or not re.match(url_regex, issue):
                logger.error(f"The issue label was not provided or is of incorrect format, example: https://github.com/wazuh/<repository>/issues/<issue-number>.")
                sys.exit(1)
            if params.instance_name:
                name = params.instance_name
            else:
                issue_name= re.search(r'github\.com\/wazuh\/([^\/]+)\/issues', issue)
                repository = cls.generate_repository_name(str(issue_name.group(1)))
                name = repository + "-" + str(re.search(r'(\d+)$', issue).group(1)) + "-" + str(params.composite_name.split("-")[1]) + "-" + str(params.composite_name.split("-")[2])

            # Keys.
            if not ssh_key:
                logger.debug(f"Generating new key pair")
                credentials.generate(temp_dir, str('-'.join(name.split("-")[:-2])))
            else:
                logger.debug(f"Using provided key pair")
                key_id = credentials.ssh_key_interpreter(ssh_key)
                credentials.load(key_id)
            # Parse the config if it is not provided.
            config = cls.__parse_config(params, credentials, issue, label_team, termination_date, name)
            #Generate dedicated host for macOS instances
            if platform == 'macos':
                #host_identifier = cls._generate_dedicated_host(config, str(params.composite_name.split("-")[3]))
                host_identifier = "h-063f33be1f52efbe9"
                config = cls.__parse_config(params, credentials, issue, label_team, termination_date, name, host_identifier)
        else:
            logger.debug(f"Using provided config")
            # Load the existing credentials.
            credentials.load(config.key_name)
            # Create the temp directory.
            # TODO: Review this on the credentials refactor.
        if not temp_dir.exists():
            logger.debug(f"Creating temp directory: {temp_dir}")
            temp_dir.mkdir(parents=True, exist_ok=True)
        # Generate the instance.
        instance_id = cls.__create_ec2_instance(config)
        # Rename the temp directory to its real name.
        instance_dir = Path(base_dir, instance_id)
        logger.debug(f"Renaming temp {temp_dir} directory to {instance_dir}")
        os.rename(temp_dir, instance_dir)
        if not ssh_key:
            credentials.key_path = (instance_dir / credentials.name)
        else:
            credentials.key_path = (os.path.splitext(ssh_key)[0])

        return AWSInstance(instance_dir, instance_id, platform, credentials, host_identifier, None, None, arch, None, config.user)

    @staticmethod
    def _load_instance(instance_dir: Path, instance_id: str) -> AWSInstance:
        """
        Load an existing AWS EC2 instance.

        Args:
            instance_dir (Path): Directory where instance data is stored.
            instance_id (str): Identifier of the instance.

        Returns:
            AWSInstance: Loaded AWSInstance object.
        """
        return AWSInstance(instance_dir, instance_id)

    @classmethod
    def _destroy_instance(cls, instance_dir: str, identifier: str, key_path: str, platform: str, host_identifier: str = None, host_instance_dir: str | Path = None, ssh_port: str = None, arch: str = None) -> None:
        """
        Destroy an AWS EC2 instance.

        Args:
            instance_dir (str): Directory where instance data is stored.
            identifier (str): Identifier of the instance.
            key_path (str): Path to the key pair.
            platform (str): Platform of the instance.
            host_identifier (str, optional): Identifier of the dedicated host. Defaults to None.
            host_instance_dir (str | Path, optional): Directory of the host instance. Defaults to None.
            ssh_port (str, optional): SSH port of the instance. Defaults to None.
            arch (str, optional): Architecture of the instance. Defaults to None.
        """
        credentials = AWSCredentials()
        key_id = os.path.basename(key_path)
        credentials.load(key_id)
        instance = AWSInstance(instance_dir, identifier, platform, credentials, host_identifier)
        if os.path.dirname(key_path) == str(instance_dir):
            logger.debug(f"Deleting credentials: {instance.credentials.name}")
            instance.credentials.delete()
        instance.delete()
        if host_identifier != "None" and host_identifier is not None:
            cls._release_dedicated_host(host_identifier)

    @staticmethod
    def __create_ec2_instance(config: AWSConfig) -> str:
        """
        Create an AWS EC2 instance.

        Args:
            config (AWSConfig): Configuration for the instance.

        Returns:
            str: Identifier of the created instance.
        """
        client = boto3.resource('ec2')

        params = {
            'ImageId': config.ami,
            'InstanceType': config.type,
            'KeyName': config.key_name,
            'SecurityGroupIds': config.security_groups,
            'MinCount': 1,
            'MaxCount': 1,
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': config.name},
                    {'Key': 'termination_date', 'Value': config.termination_date},
                    {'Key': 'issue', 'Value': config.issue},
                    {'Key': 'team', 'Value': config.team}
                ]
            }]
        }

        if config.host_identifier:
            params['Placement'] = {'AvailabilityZone': config.zone, 'HostId': config.host_identifier}

        instance = client.create_instances(**params)[0]
        # Wait until the instance is running.
        instance.wait_until_running()
        return instance.instance_id

    @classmethod
    def __parse_config(cls, params: CreationPayload, credentials: AWSCredentials, issue: str, team: str, termination_date: str, name: str, host_identifier: str = None) -> AWSConfig:
        """
        Parse configuration parameters for creating an AWS EC2 instance.

        Args:
            params (CreationPayload): Payload containing creation parameters.
            credentials (AWSCredentials): AWS credentials object.
            issue (str): Issue URL.
            team (str): Team label.
            termination_date (str): Termination date label.
            name (str): Name of the instance.
            host_identifier (str): Identifier of the dedicated host.

        Returns:
            AWSConfig: Parsed AWSConfig object.
        """
        config = {}

        # Get the specs from the yamls.
        size_specs = cls._get_size_specs()[params.size]
        os_specs = cls._get_os_specs()[params.composite_name]
        mics_specs = cls._get_misc_specs()
        arch = params.composite_name.split('-')[-1]
        platform = str(params.composite_name.split("-")[0])

        # Parse the configuration.
        if platform == 'macos':
            os_specs['zone'] = os_specs['zone'] + 'c'
            if arch == 'arm64':
                config['type'] = 'mac2.metal'
            if arch == 'amd64':
                config['type'] = 'mac1.metal'
        else:
            for spec in size_specs:
                if fnmatch.fnmatch(arch, spec):
                    config['type'] = size_specs[spec]['type']
                    break

        config['ami'] = os_specs['ami']
        config['zone'] = os_specs['zone']
        config['user'] = os_specs['user']
        config['key_name'] = credentials.name
        config['security_groups'] = mics_specs['security-group']
        config['termination_date'] = termination_date
        config['issue'] = issue
        config['team'] = team
        config['name'] = name
        if host_identifier:
            config['host_identifier'] = host_identifier
        config['platform'] = platform

        return AWSConfig(**config)

    @staticmethod
    def _generate_dedicated_host(config: AWSConfig, arch: str) -> str:
        """
        Generate a dedicated host for macOS instances.

        Args:
            config (AWSConfig): Configuration for the instance.

        Returns:
            str: Identifier of the created dedicated host.
        """
        client = boto3.client('ec2')
        dedicated_host_name = str(config.name) + '-Host-' + arch
        logger.info(f"Creating dedicated host: {dedicated_host_name}")
        host = client.allocate_hosts(InstanceType=config.type,
                                        AutoPlacement='on',
                                        AvailabilityZone=config.zone,
                                        Quantity=1,
                                        TagSpecifications=[{
                                            'ResourceType': 'dedicated-host',
                                            'Tags': [
                                                {'Key': 'Name', 'Value': dedicated_host_name},
                                                {'Key': 'termination_date', 'Value': config.termination_date},
                                                {'Key': 'issue', 'Value': config.issue},
                                                {'Key': 'team', 'Value': config.team}
                                            ]
                                        }])
        logger.info(f"Dedicated host created: {host['HostIds'][0]}")
        return host['HostIds'][0]

    @staticmethod
    def _release_dedicated_host(host_identifier: str) -> str:
        """
        Release a dedicated host.

        Args:
            host_identifier (str): Identifier of the dedicated host.

        Returns:
            str: Identifier of the released dedicated host.
        """
        client = boto3.client('ec2')
        logger.info(f"Releasing dedicated host: {host_identifier}")
        host = client.release_hosts(HostIds=[host_identifier])
        if host['Unsuccessful']:
            unsuccessful_messages = [item['Error']['Message'] for item in host['Unsuccessful']]
            for message in unsuccessful_messages:
                logger.info(f"{message}")
        else:
            logger.info(f"Dedicated host released: {host_identifier}")

    @staticmethod
    def generate_repository_name(repository: str) -> str:
        """
        Generate a repository name for the instance.

        Args:
            repository (str): Repository name.

        Returns:
            str: Repository name for the instance.
        """
        matches = re.findall(r'(\w+)', repository)
        if len(matches) == 3:
            return ''.join([c[0] for c in matches])
        elif len(matches) == 2:
            return matches[1]
        else:
            return repository
