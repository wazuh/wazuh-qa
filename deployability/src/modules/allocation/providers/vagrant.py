from pathlib import Path
import re
import subprocess
import uuid
import jinja2

from fnmatch import fnmatch

from ..credentials.vagrant import VagrantCredential
from ..models import Instance, InstanceParams, Inventory, VagrantConfig
from .base import Provider, TEMPLATES_DIR


class VagrantProvider(Provider):

    def __init__(self, base_dir: Path | str, name: str, instance_params: InstanceParams) -> None:
        super().__init__(base_dir, name, instance_params)

    def create(self) -> Instance:
        if self.instance:
            return self.instance
        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)

        priv = self.key_pair.get('private')
        pub = self.key_pair.get('public')
        self.config = self._parse_config()
        self.instance = self._generate_instance(priv)
        # Render and write Vagrantfile
        vagrantfile = self._render_vagrantfile(pub)
        self._save_vagrantfile(vagrantfile)

        return self.instance

    def start(self) -> Inventory:
        if not self.instance:
            return
        self._run_vagrant_command('up')
        self.inventory = self._parse_inventory()

        return self.inventory

    def stop(self):
        if not self.instance:
            return
        self._run_vagrant_command('halt')

    def destroy(self):
        if not self.instance:
            return
        self._run_vagrant_command('destroy -f')

    def status(self):
        if not self.instance:
            return
        self._run_vagrant_command('status')

    def delete(self):
        if not self.instance:
            return
        self.destroy()
        self.working_dir.rmdir()
        self.inventory = None
        self.instance = None

    # Private methods

    def _parse_inventory(self) -> Inventory:
        inventory = {}
        private_key = self.key_pair.get('private')
        ssh_config = self._run_vagrant_command('ssh-config')
        patterns = {'ansible_hostname': r'HostName (.*)',
                    'ansible_user': r'User (.*)',
                    'ansible_port': r'Port (.*)'}

        inventory['ansible_ssh_private_key_file'] = private_key
        for key, pattern in patterns.items():
            match = re.search(pattern, ssh_config)
            if match:
                inventory[key] = match.group(1)
            else:
                raise ValueError(f"Couldn't find {key} in vagrant ssh-config")

        return Inventory(**inventory)

    def _parse_config(self) -> VagrantConfig:
        config = {}

        composite_name = self.instance_params.composite_name
        roles = self._get_role_specs('vagrant')
        os_specs = self._get_os_specs('vagrant')

        config['id'] = self.__generate_instance_id()
        config['box'] = os_specs[composite_name]['box']
        config['box_version'] = os_specs[composite_name]['box_version']
        for pattern, specs in roles[self.instance_params.role].items():
            if fnmatch(composite_name, pattern):
                config['cpu'] = specs['cpu']
                config['memory'] = specs['memory']
                config['ip'] = specs['ip']
                break

        return VagrantConfig(**config)

    def _generate_instance(self) -> Instance:
        instance = Instance(name=self.name,
                            params=self.instance_params,
                            path=self.working_dir,
                            provider='vagrant',
                            credential=self.key_pair.get('private'),
                            connection_info=None,
                            provider_config=self.config)
        return instance

    def _generate_key_pair(self) -> tuple[str, str]:
        cred = VagrantCredential(self.working_dir, self.name)
        private, public = cred.generate_key()
        return {'private': private, 'public': public}

    def __generate_instance_id(self, prefix: str = "VAGRANT") -> str:
        """Generates a random instance name with the given prefix."""
        return f"{prefix}-{uuid.uuid4()}"

    def _run_vagrant_command(self, command: str):
        output = subprocess.run(["vagrant", command],
                                cwd=self.base_dir,
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return output.stdout.decode("utf-8")

    def _render_vagrantfile(self, credential: str) -> str:
        template_path = TEMPLATES_DIR / 'vagrant'
        template_loader = jinja2.FileSystemLoader(searchpath=template_path)
        template_env = jinja2.Environment(loader=template_loader)
        loaded_template = template_env.get_template(template_path)

        return loaded_template.render(config=self.config, credential=credential)

    def _save_vagrantfile(self, vagrantfile: str) -> None:
        with open(self.working_dir / 'Vagrantfile', 'w') as f:
            f.write(vagrantfile)
