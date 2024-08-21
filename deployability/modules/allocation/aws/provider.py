# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import boto3
import fnmatch
import os
import re
import random
from pathlib import Path
from datetime import datetime, timedelta
import subprocess

from modules.allocation.generic import Provider
from modules.allocation.generic.models import CreationPayload, InstancePayload
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
        cls.validate_dependencies()
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
            if not termination_date:
                raise ValueError(f"The termination_date label was not provided.")
            elif re.match(r'^\d+d$', termination_date):
                new_date = datetime.now() + timedelta(days=int(termination_date.split("d")[0]))
                termination_date = new_date.strftime("%Y-%m-%d %H:%M:%S")
            elif not re.match(date_regex, termination_date):
                raise ValueError(f"The termination_date label was not provided or is of incorrect format, example: 2021-12-31 23:59:59 or 2d")
            if label_team:
                not_match = 0
                for team in teams:
                    if label_team == team:
                        label_team = team
                        break
                    else:
                        not_match += 1
                if not_match == len(teams):
                    raise ValueError(f"The team label provided does not match any of the available teams. Available teams: {teams}")
            else:
                raise ValueError(f"The team label was not provided. Availables teams: {teams}.")
            if params.instance_name:
                name = params.instance_name
            elif issue:
                if not re.match(url_regex, issue):
                    raise ValueError(f"The issue label was not provided or is of incorrect format, example: https://github.com/wazuh/<repository>/issues/<issue-number>")
                issue_name= re.search(r'github\.com\/wazuh\/([^\/]+)\/issues', issue)
                repository = cls.generate_repository_name(str(issue_name.group(1)))
                name = repository + "-" + str(re.search(r'(\d+)$', issue).group(1)) + "-" + str(params.composite_name.split("-")[1]) + "-" + str(params.composite_name.split("-")[2])
            else:
                name = str(params.composite_name.split("-")[1]) + "-" + str(params.composite_name.split("-")[2]) + "-" + str(params.composite_name.split("-")[3])

            # Keys.
            if platform == "windows":
                credentials.create_password()
            elif not ssh_key:
                logger.debug(f"Generating new key pair")
                credentials.generate(temp_dir, name + "-key-" + str(random.randint(1000, 9999)))
            else:
                logger.debug(f"Using provided key pair")
                key_id = credentials.ssh_key_interpreter(ssh_key)
                credentials.load(key_id)
            # Parse the config if it is not provided.
            config = cls.__parse_config(params, credentials, issue, label_team, termination_date, name)
            #Generate dedicated host for macOS instances
            if platform == 'macos':
                host_identifier = cls._generate_dedicated_host(config, str(params.composite_name.split("-")[3]))
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
        while True:
            instance_dir = Path(base_dir, f"{name}-{str(random.randint(0000, 9999))}")
            if not instance_dir.exists():
                break
        logger.debug(f"Renaming temp {temp_dir} directory to {instance_dir}")
        os.rename(temp_dir, instance_dir)
        if platform != "windows":
            if not ssh_key:
                credentials.key_path = (instance_dir / credentials.name)
            else:
                credentials.key_path = (os.path.splitext(ssh_key)[0])

        instance_params = {}
        instance_params['instance_dir'] = instance_dir
        instance_params['name'] = config.name
        instance_params['identifier'] = instance_id
        instance_params['platform'] = platform
        instance_params['host_identifier'] = host_identifier
        instance_params['arch'] = arch
        instance_params['user'] = config.user
        return AWSInstance(InstancePayload(**instance_params), credentials)

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
        instance_params = {}
        instance_params['instance_dir'] = instance_dir
        instance_params['identifier'] = instance_id
        return AWSInstance(InstancePayload(**instance_params))

    @classmethod
    def _destroy_instance(cls, destroy_parameters: InstancePayload) -> None:
        """
        Destroy an AWS EC2 instance.

        Args:
            destroy_parameters (InstancePayload): The parameters for destroying the instance.
        """
        credentials = AWSCredentials()
        if destroy_parameters.platform != 'windows':
            key_id = os.path.basename(destroy_parameters.key_path)
            credentials.load(key_id)
        instance_params = {}
        instance_params['instance_dir'] = destroy_parameters.instance_dir
        instance_params['identifier'] = destroy_parameters.identifier
        instance_params['platform'] = destroy_parameters.platform
        instance_params['host_identifier'] = destroy_parameters.host_identifier

        instance = AWSInstance(InstancePayload(**instance_params), credentials)
        if os.path.dirname(destroy_parameters.key_path) == str(destroy_parameters.instance_dir) and destroy_parameters.platform != 'windows':
            logger.debug(f"Deleting credentials: {instance.credentials.name}")
            instance.credentials.delete()
        instance.delete()
        if destroy_parameters.host_identifier != "None" and destroy_parameters.host_identifier is not None:
            cls._release_dedicated_host(destroy_parameters.host_identifier)

    @staticmethod
    def __create_ec2_instance(config: AWSConfig) -> str:
        """
        Create an AWS EC2 instance.

        Args:
            config (AWSConfig): Configuration for the instance.

        Returns:
            str: Identifier of the created instance.
        """
        client = boto3.client('ec2')
        resource = boto3.resource('ec2')

        userData_file = Path(__file__).parent.parent / 'aws' / 'helpers' / 'userData.sh'
        windosUserData_file = Path(__file__).parent.parent / 'aws' / 'helpers' / 'windowsUserData.ps1'
        # Describe the AMI to get the root device name
        ami = client.describe_images(ImageIds=[config.ami])
        root_device_name = ami['Images'][0]['RootDeviceName']
        ami_storage = ami['Images'][0]['BlockDeviceMappings'][0]['Ebs']['VolumeSize']

        if ami_storage > config.storage:
            config.storage = ami_storage

        if config.platform == 'windows':
            with open(windosUserData_file, 'r') as file:
                userData = file.read()
                userData = userData.replace('ChangeMe', config.key_name)
        else:
            with open(userData_file, 'r') as file:
                userData = file.read()
        params = {
            'ImageId': config.ami,
            'InstanceType': config.type,
            'SecurityGroupIds': config.security_groups,
            'BlockDeviceMappings': [
                {
                    'DeviceName': root_device_name,
                    'Ebs': {

                        'DeleteOnTermination': True,
                        'VolumeSize': config.storage,
                        'VolumeType': 'gp2'
                    },
                },
            ],
            'MinCount': 1,
            'MaxCount': 1,
            'UserData': userData,
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': config.name},
                    {'Key': 'termination_date', 'Value': config.termination_date},
                    {'Key': 'team', 'Value': config.team}
                ]
            }]
        }
        if config.platform != 'windows':
            params['KeyName'] = config.key_name


        if config.host_identifier:
            params['Placement'] = {'AvailabilityZone': config.zone, 'HostId': config.host_identifier}

        if config.issue:
            params['TagSpecifications'][0]['Tags'].append({'Key': 'issue', 'Value': config.issue})

        instance = resource.create_instances(**params)[0]
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
        size_specs = cls._get_size_specs(params.size)
        os_specs = cls._get_os_specs(params.composite_name)
        mics_specs = cls._get_misc_specs()
        arch = params.composite_name.split('-')[-1]
        platform = str(params.composite_name.split("-")[0])

        # Parse the configuration.
        if platform == 'macos':
            os_specs['zone'] = os_specs['zone'] + 'c'
            config['storage'] = 0
            if arch == 'arm64':
                config['type'] = 'mac2.metal'
            if arch == 'amd64':
                config['type'] = 'mac1.metal'
        else:
            for spec in size_specs:
                if fnmatch.fnmatch(arch, spec):
                    config['type'] = size_specs[spec]['type']
                    config['storage'] = int(size_specs[spec]['storage'])
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
        params = {
            'InstanceType': config.type,
            'AutoPlacement': 'on',
            'AvailabilityZone': config.zone,
            'Quantity': 1,
            'TagSpecifications': [{
                'ResourceType': 'dedicated-host',
                'Tags': [
                    {'Key': 'Name', 'Value': config.name},
                    {'Key': 'termination_date', 'Value': config.termination_date},
                    {'Key': 'team', 'Value': config.team}
                ]
            }]
        }
        if config.issue:
            params['TagSpecifications'][0]['Tags'].append({'Key': 'issue', 'Value': config.issue})
        host = client.allocate_hosts(**params)
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
                logger.warning(f"{message}")
        else:
            logger.info(f"Dedicated host released: {host_identifier}")

    @staticmethod
    def validate_dependencies():
        """
        Validates the dependencies for the Vagrant provider.

        Raises:
            ValueError: If the dependencies are not met.
        """
        dependencies = ['openssh-client', 'awscli']
        missing_dependencies = []

        result = subprocess.run(['which', 'apt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise ValueError("The Allocation module works on systems with APT as packages systems.")

        for dependency in dependencies:
            result = subprocess.run(['bash', '-c', f"apt list --installed 2>/dev/null | grep -q -E ^{dependency}*"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                if dependency == 'awscli':
                    aws_binary = subprocess.run(['which', 'aws'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if aws_binary.returncode != 0:
                        missing_dependencies.append(dependency)
                else:
                    missing_dependencies.append(dependency)

        if len(missing_dependencies) > 0:
            if len(missing_dependencies) == 1:
                raise ValueError(f"Missing dependency: {missing_dependencies[0]}")
            else:
                raise ValueError(f"Missing dependencies: {missing_dependencies}")
