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
    provider_name = 'aws'
    _client = boto3.resource('ec2')

    @classmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload) -> AWSInstance:
        temp_id = cls._generate_instance_id(cls.provider_name)
        temp_dir = base_dir / temp_id
        # Generate the credentials.
        credentials = AWSCredentials()
        credentials.generate(temp_dir, temp_id)
        # Parse the config and create the AWS EC2 instance.
        config = cls.__parse_config(params, credentials)
        _instance = cls._client.create_instances(ImageId=config.ami,
                                                 InstanceType=config.type,
                                                 KeyName=config.key_name,
                                                 SecurityGroupIds=config.security_groups,
                                                 MinCount=1, MaxCount=1)[0]
        _instance.wait_until_running()  # Wait until the instance is running.
        # Rename the temp directory to its real name.
        instance_dir = Path(base_dir, _instance.instance_id)
        os.rename(temp_dir, instance_dir)
        temp_dir.rmdir()  # Remove the temp directory.
        return AWSInstance(instance_dir, _instance.instance_id, credentials, config.user)

    @staticmethod
    def _load_instance(instance_dir: Path, instance_id: str) -> AWSInstance:
        return AWSInstance(instance_dir, instance_id)

    @classmethod
    def _destroy_instance(cls, instance_dir: str, identifier: str) -> None:
        instance = AWSInstance(instance_dir, identifier)
        instance.delete()

    @classmethod
    def __parse_config(cls, params: CreationPayload, credentials: AWSCredentials) -> AWSConfig:
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
