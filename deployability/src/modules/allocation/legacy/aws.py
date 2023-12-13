import boto3
import shutil
import os
import yaml
import fnmatch


class AWSInfra():
    SPECS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'specs')
    OS_SPECS_PATH = os.path.join(SPECS_DIR, 'os.yml')
    ROLE_SPECS_PATH = os.path.join(SPECS_DIR, 'roles.yml')

    def init(self, instance_params: dict, base_dir: str, name: str):
        self.ec2 = boto3.resource('ec2')
        self.name = name
        self.instance_params = instance_params
        self.instance_dir = os.path.join(base_dir, name)
        if not os.path.exists(self.instance_dir):
            os.makedirs(self.instance_dir)
        self.credential = AWSCredential(self.name,base_dir)
        self.credential.create()
        self.connection_info = dict()
        self.provider_specific = dict()

    
    def from_db(self, db: dict, base_dir: str):
        self.ec2 = boto3.resource('ec2')
        self.name = db['name']
        self.instance_params = db['instance_params']
        self.instance_dir = db['instance_dir']
        self.credential = AWSCredential(self.name, base_dir)
        self.connection_info = db['connection_info']
        self.provider_specific = db['provider_specific']

    def dump(self):
        info = {
            'name': self.name,
            'instance_params': self.instance_params,
            'instance_dir': self.instance_dir,
            'credential': self.credential.name,
            'connection_info': self.connection_info,
            'provider_specific': self.provider_specific
        }
        return { self.name: info}

    def ansible_inventory(self):
        connection = dict()
        connection['ansible_host'] = self.connection_info['hostname']
        connection['ansible_user'] = self.connection_info['user']
        connection['ansible_port'] = self.connection_info['port']
        connection['ansible_ssh_private_key_file'] = self.connection_info['key']
        return {self.instance_params['alias']: connection}

    def create(self):
        with open(AWSInfra.ROLE_SPECS_PATH, "r") as roles_file:
            roles = yaml.safe_load(roles_file)
            for pattern, specs in roles[self.instance_params['role']].items():
                if fnmatch.fnmatch(self.instance_params['composite-name'], pattern):
                    self.provider_specific['type'] = specs['type']
                    break
        with open(AWSInfra.OS_SPECS_PATH, "r") as os_file:
            os_specs = yaml.safe_load(os_file)
            self.provider_specific['ami'] = os_specs[self.instance_params['composite-name']]['ami']
            self.provider_specific['zone'] = os_specs[self.instance_params['composite-name']]['zone']
            self.provider_specific['user'] = os_specs[self.instance_params['composite-name']]['user']

        request_params = {
            'ImageId': self.provider_specific['ami'],
            'InstanceType': self.provider_specific['type'],
            'KeyName': self.credential.name,
            'MinCount':1,
            'MaxCount': 1,
            'TagSpecifications' : [
                {
                'ResourceType': 'instance',
                'Tags': [
                {
                    'Key': 'Name',
                    'Value': f"dtt1-{self.name}"
                }]
                }
            ]
        }
        instance = self.ec2.create_instances(**request_params)[0]
        instance.wait_until_running()
        instance.reload()
        self.provider_specific['instance_id'] = instance.id
        self.connection_info['hostname'] = instance.private_ip_address
        self.connection_info['user'] = self.provider_specific['user']
        self.connection_info['port'] = 22
        self.connection_info['key'] = os.path.join(self.instance_dir, self.credential.name + '.pem')

    def start(self):
        pass

    def stop(self):
        pass

    def status(self):
        self.ec2.describe_instances(InstanceIds=[self.provider_specific['instance_id']])

    def delete(self):
        self.credential.delete()
        self.ec2.instances.filter(InstanceIds=[self.provider_specific['instance_id']]).terminate()
        shutil.rmtree(self.instance_dir)

class AWSCredential():
    def __init__(self, name, base_dir):
        self.name = name
        self.ec2 = boto3.resource('ec2')
        self.base_dir = os.path.join(base_dir, name)

    def create(self):
        response = self.ec2.create_key_pair(KeyName=str(self.name))
        with open(os.path.join(self.base_dir, self.name) + '.pem', 'w') as key_file:
            key_file.write(response.key_material)
        os.chmod(os.path.join(self.base_dir, self.name) + '.pem', 0o600)

    def delete(self):
        self.ec2.KeyPair(self.name).delete()
        os.remove(os.path.join(self.base_dir, self.name) + '.pem')
        
