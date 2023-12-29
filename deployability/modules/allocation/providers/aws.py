import fnmatch
import os
import boto3
from pathlib import Path

from modules.allocation.credentials.aws import AWSCredentials
from modules.allocation.instances.aws import AmazonEC2Instance
from .generic import InstanceParams, Provider


class AWSProvider(Provider):
    provider_name = 'aws'
    _client = boto3.resource('ec2')

    @staticmethod
    def load_instance(base_dir,instance_id: str) -> None:
        if not base_dir.exists():
            raise Exception(f"Instance path {base_dir} does not exist")

        instance = AmazonEC2Instance(base_dir, instance_id)
        return instance

    @classmethod
    def create_instance(cls, base_dir: Path, params: InstanceParams, credentials: AWSCredentials = None) -> AmazonEC2Instance:
        base_dir = Path(base_dir)
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        elif not base_dir.is_dir():
            raise Exception(f"Instance path {base_dir} is not a dir.")
        temp_id = cls._generate_instance_id(cls.provider_name)
        temp_dir = Path(base_dir, 'temp', temp_id)
        if not credentials:
            credentials = AWSCredentials()
            credentials.generate(temp_dir, 'instance_key')
        elif not isinstance(credentials, AWSCredentials):
            raise Exception(f"Invalid credentials type: {type(credentials)}")
        config = cls._parse_config(params, credentials)
        _instance = cls._client.create_instances(ImageId=config['ami'],
                                                InstanceType=config['type'],
                                                KeyName=config['key_name'],
                                                SecurityGroupIds=config['security_groups'],
                                                MinCount=1, MaxCount=1)[0]
        _instance.wait_until_running()
        instance_dir = Path(base_dir, _instance.instance_id)
        if instance_dir.exists():
            instance_dir.unlink()
        os.rename(temp_dir, instance_dir)
        return AmazonEC2Instance(instance_dir, _instance.instance_id, credentials)
    
    @classmethod
    def destroy_instance(instance_dir: str, identifier: str) -> None:
        instance = AmazonEC2Instance(instance_dir, identifier)
        instance.delete()

    @classmethod
    def _parse_config(cls, params: InstanceParams, credentials: AWSCredentials) -> None:
        config = {}
        size_specs = cls._get_size_specs()[params.size]
        os_specs = cls._get_os_specs()[params.composite_name]
        mics_specs = cls._get_misc_specs()
        for spec in size_specs:
            if fnmatch.fnmatch(params.composite_name, spec):
                config['type'] = size_specs[spec]['type']
                break
        config['ami'] = os_specs['ami']
        config['zone'] = os_specs['zone']
        config['user'] = os_specs['user']
        config['key_name'] = credentials.name
        config['security_groups'] = mics_specs['security-group']
        return config
