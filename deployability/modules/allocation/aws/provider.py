import boto3
import fnmatch
import os
from pathlib import Path

from modules.allocation.generic import Provider
from modules.allocation.generic.models import CreationPayload
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
    _client = boto3.resource('ec2')

    @classmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload) -> AWSInstance:
        """
        Create an AWS EC2 instance.

        Args:
            base_dir (Path): Base directory for storing instance data.
            params (CreationPayload): Payload containing creation parameters.

        Returns:
            AWSInstance: Created AWSInstance object.
        """
        temp_id = cls._generate_instance_id(cls.provider_name)
        temp_dir = base_dir / temp_id
        # Generate the credentials.
        credentials = AWSCredentials()
        credentials.generate(temp_dir, temp_id.split('-')[-1] + '_key')
        # Parse the config and create the AWS EC2 instance.
        config = cls._parse_config(params, credentials)
        _instance = cls._client.create_instances(ImageId=config.ami,
                                                 InstanceType=config.type,
                                                 KeyName=config.key_name,
                                                 SecurityGroupIds=config.security_groups,
                                                 MinCount=1, MaxCount=1)[0]
        # Wait until the instance is running.
        _instance.wait_until_running()  
        # Rename the temp directory to its real name.
        instance_dir = Path(base_dir, _instance.instance_id)
        os.rename(temp_dir, instance_dir)
        credentials.key_path = (instance_dir / credentials.name).with_suffix('.pem')

        return AWSInstance(instance_dir, _instance.instance_id, credentials, config.user)

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
    def _destroy_instance(cls, instance_dir: str, identifier: str) -> None:
        """
        Destroy an AWS EC2 instance.

        Args:
            instance_dir (str): Directory where instance data is stored.
            identifier (str): Identifier of the instance.
        """
        instance = AWSInstance(instance_dir, identifier)
        instance.delete()

    @classmethod
    def _parse_config(cls, params: CreationPayload, credentials: AWSCredentials) -> AWSConfig:
        """
        Parse configuration parameters for creating an AWS EC2 instance.

        Args:
            params (CreationPayload): Payload containing creation parameters.
            credentials (AWSCredentials): AWS credentials object.

        Returns:
            AWSConfig: Parsed AWSConfig object.
        """
        config = {}

        # Get the specs from the yamls.
        size_specs = cls._get_size_specs()[params.size]
        os_specs = cls._get_os_specs()[params.composite_name]
        mics_specs = cls._get_misc_specs()
        # Parse the configuration.
        for spec in size_specs:
            if fnmatch.fnmatch(params.composite_name, spec):
                config['type'] = size_specs[spec]['type']
                break

        config['ami'] = os_specs['ami']
        config['zone'] = os_specs['zone']
        config['user'] = os_specs['user']
        config['key_name'] = credentials.name
        config['security_groups'] = mics_specs['security-group']

        return AWSConfig(**config)
