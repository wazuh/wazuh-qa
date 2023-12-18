import fnmatch
import shutil
import subprocess
import os
import yaml
import shutil



class VagrantInfra():
    SPECS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'specs')
    OS_SPECS_PATH = os.path.join(SPECS_DIR, 'os.yml')
    ROLE_SPECS_PATH = os.path.join(SPECS_DIR, 'roles.yml')

    def init(self, instance_params: dict, base_dir: str, name: str):
        self.name = name
        self.instance_params = instance_params
        self.instance_dir = os.path.join(base_dir, name)
        if not os.path.exists(self.instance_dir):
            os.makedirs(self.instance_dir)
        self.credentials = VagrantCredentialss(self.name, base_dir)
        self.credentials.create()
        self.connection_info = dict()
        self.provider_specific = dict()

    
    def from_db(self, db: dict, base_dir: str):
        self.name = db['name']
        self.instance_params = db['instance_params']
        self.instance_dir = db['instance_dir']
        self.credentials = db['credential']
        self.connection_info = db['connection_info']
        self.provider_specific = db['provider_specific']


    def dump(self):
        info = {
            'name': self.name,
            'instance_params': self.instance_params,
            'instance_dir': self.instance_dir,
            'credential': self.credentials.name,
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
        if self.instance_params['role'] == 'manager':
            connection['install'] = [ {'type':'package', 'component':'wazuh-manager'}]
        elif self.instance_params['role'] == 'agent':
            connection['install'] = [ {'type':'package', 'component':'wazuh-agent'}]
        return {self.instance_params['alias']: connection}

    def create(self):
        with open(VagrantInfra.ROLE_SPECS_PATH, "r") as roles_file:
            roles = yaml.safe_load(roles_file)
            for pattern, specs in roles[self.instance_params['role']].items():
                if fnmatch.fnmatch(self.instance_params['composite-name'], pattern):
                    self.provider_specific['cpu'] = specs['cpu']
                    self.provider_specific['memory'] = specs['memory']
                    self.provider_specific['ip'] = specs['ip']
                    break
        with open(VagrantInfra.OS_SPECS_PATH, "r") as os_file:
            os_specs = yaml.safe_load(os_file)
            self.provider_specific['box'] = os_specs[self.instance_params['composite-name']]['box']
            self.provider_specific['box_version'] = os_specs[self.instance_params['composite-name']]['box_version']


        VAGRANTFILE_TEMPLATE = f"""
        Vagrant.configure("2") do |config|
            config.vm.box = "{self.provider_specific['box']}"
            config.vm.box_version = "{self.provider_specific['box_version']}"
            config.vm.provision "file", source: "{self.credentials.name}.pub", destination: ".ssh/authorized_keys"
            config.vm.network "private_network", ip:"{self.provider_specific['ip']}"
            config.vm.provider "virtualbox" do |v|
                v.memory = {self.provider_specific['memory']}
                v.cpus = {self.provider_specific['cpu']}
            end
        end
        """
        with open(os.path.join(self.instance_dir, "Vagrantfile"), "w", encoding="utf-8") as f:
            f.write(VAGRANTFILE_TEMPLATE)

    def delete(self):
        subprocess.run(["vagrant", "destroy", "-f"], cwd=self.instance_dir, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
        shutil.rmtree(self.instance_dir)

    def start(self):
        subprocess.run(["vagrant", "up"], cwd=self.instance_dir, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
        out = subprocess.run(["vagrant", "ssh-config"], cwd=self.instance_dir, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
        self.connection_info = dict()
        for line in out.stdout.decode("utf-8").splitlines():
            if line.startswith("  HostName "):
                self.connection_info['hostname'] = line.split()[1]
            elif line.startswith("  User "):
                self.connection_info['user'] = line.split()[1]
            elif line.startswith("  Port "):
                self.connection_info['port'] = line.split()[1]
        self.connection_info['key'] = os.path.join(self.instance_dir, self.credentials.name)

    def stop(self):
        subprocess.run(["vagrant", "halt"], cwd=self.instance_dir, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    def status(self):
        subprocess.run(["vagrant", "status"], cwd=self.instance_dir, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

class VagrantCredentialss():
    def __init__(self, name, base_dir):
        self.name = name
        self.base_dir = os.path.join(base_dir, name)

    def create(self):
        command = ["ssh-keygen",
                        "-f", os.path.join(self.base_dir, self.name),
                        "-m", "PEM",
                        "-t", "rsa",
                        "-N", "",
                        "-q"]
        output = subprocess.run(command, check=True)
        os.chmod(os.path.join(self.base_dir, self.name), 0o600)
        if output.returncode != 0:
            raise Exception("Error creating key pair")

    def delete(self):
        os.remove(self.name)
        os.remove(self.name + ".pub")