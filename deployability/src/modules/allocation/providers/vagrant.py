from pathlib import Path
import re
import subprocess
import jinja2
import yaml
from fnmatch import fnmatch

from ..credentials.vagrant import VagrantCredential
from ..models import Instance, InstanceParams, VagrantConfig
from .base import Provider, TEMPLATES_DIR


class VagrantProvider(Provider):

    def __init__(self, instance_params: InstanceParams, working_dir: str):
        super().__init__(instance_params, working_dir=working_dir)

    def create(self, instance_params: InstanceParams, working_dir: str):
        credential = self._generate_credentials(instance_params, working_dir)
        config = self._get_config(instance_params)
        vagrantfile = self._render_vagrantfile(config, credential)

        self.instance = self._generate_instance(instance_params, working_dir, credential, config)

        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)

        with open(self.working_dir / 'Vagrantfile', 'w') as f:
            f.write(vagrantfile)

    def start(self):
        if not self.instance:
            return
        self._run_vagrant_command('up')
        ssh_config = self._run_vagrant_command('ssh-config')
        connection_info = self._get_connection_info(ssh_config)
        self.instance.connection_info = connection_info

    def stop(self):
        if not self.instance:
            return
        self._run_vagrant_command('halt')

    def delete(self):
        if not self.instance:
            return
        self._run_vagrant_command('destroy -f')

    def status(self):
        if not self.instance:
            return
        self._run_vagrant_command('status')

    def generate_inventory(self):
        pass

    def _generate_instance(self, instance_params: InstanceParams, path: str, credential: str, config: dict) -> Instance:
        instance = Instance(name=instance_params.name,
                            params=instance_params,
                            path=path,
                            provider='vagrant',
                            credential=credential,
                            connection_info=None,
                            provider_config=config)
        return instance

    # def _get_connection_info(self, connection_config: str, credential: str) -> dict:
    #     connection_info = {}
    #     for line in connection_config.splitlines():
    #         if line.startswith("  HostName "):
    #             connection_info['hostname'] = line.split()[1]
    #         elif line.startswith("  User "):
    #             connection_info['user'] = line.split()[1]
    #         elif line.startswith("  Port "):
    #             connection_info['port'] = line.split()[1]
    #     connection_info['key'] = credential

    #     return connection_info

    def _get_connection_info(self, connection_config: str, credential: str) -> dict:
        connection_info = {}
        patterns = {'hostname': r'HostName (.*)',
                    'user': r'User (.*)',
                    'port': r'Port (.*)'}

        for key, pattern in patterns.items():
            match = re.search(pattern, connection_config)
            if match:
                connection_info[key] = match.group(1)
            else:
                raise ValueError(f"Couldn't find {key} in connection_config")

        connection_info['key'] = credential

        return connection_info

    def _generate_credentials(self, name: str, path: str):
        credential = VagrantCredential(name, path)
        credential.create()
        return credential.name

    def _run_vagrant_command(self, command: str):
        output = subprocess.run(["vagrant", command],
                                cwd=self.working_dir,
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return output.stdout.decode("utf-8")

    def _get_config(self, instance_params: InstanceParams) -> VagrantConfig:
        config = {}

        composite_name = instance_params.composite_name
        roles = self._get_role_specs('vagrant')
        os_specs = self._get_os_specs('vagrant')

        config['box'] = os_specs[composite_name]['box']
        config['box_version'] = os_specs[composite_name]['box_version']
        for pattern, specs in roles[instance_params.role].items():
            if fnmatch(composite_name, pattern):
                config['cpu'] = specs['cpu']
                config['memory'] = specs['memory']
                config['ip'] = specs['ip']
                break

        return VagrantConfig(**config)

    def _render_vagrantfile(self, config: dict, credential: str) -> str:
        template_path = TEMPLATES_DIR / 'vagrant'
        template_loader = jinja2.FileSystemLoader(searchpath=template_path)
        template_env = jinja2.Environment(loader=template_loader)
        loaded_template = template_env.get_template(template_path)

        return loaded_template.render(config=config, credential=credential)
