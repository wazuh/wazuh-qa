import jinja2
import re
import subprocess
import uuid

from pathlib import Path
from fnmatch import fnmatch

from . import TEMPLATES_DIR
from .base import Provider
from ..credentials.vagrant import VagrantCredential
from ..models import Instance, InstanceParams, Inventory, VagrantConfig


class VagrantProvider(Provider):
    """A class for managing Vagrant providers.

    Attributes:
        name (str): The name of the provider.
        provider_name (str): The name of the provider.
        working_dir (Path): The working directory for the provider.
        instance_params (InstanceParams): The instance parameters.
        key_pair (dict): The key pair for the provider.
        config (ProviderConfig): The provider configuration.
        instance (Instance): The instance.
        inventory (Inventory): The inventory.
    """
    provider_name = 'vagrant'

    def __init__(self, base_dir: Path | str, name: str, instance_params: InstanceParams) -> None:
        """Initializes the VagrantProvider object.

        Args:
            base_dir (Path): The base directory for the provider.
            name (str): The name of the provider.
            instance_params (InstanceParams): The instance parameters.
        """
        super().__init__(base_dir, name, instance_params)

    def create(self) -> Instance:
        """Creates a new vagrant VM instance.

        Returns:
            Instance: The instance specifications.

        """
        if self.instance:
            return self.instance
        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)
        self.config = self.__parse_config()
        self.instance = self.__generate_instance()
        # Render and write Vagrantfile
        vagrantfile = self.__render_vagrantfile()
        self.__save_vagrantfile(vagrantfile)

        return self.instance

    def start(self) -> Inventory:
        """Starts the vagrant VM.

        Returns:
            Inventory: The ansible inventory of the instance.
        """
        if not self.instance:
            return
        self.__run_vagrant_command('up')
        self.inventory = self.__parse_inventory()

        return self.inventory

    def stop(self) -> None:
        """Stops the vagrant VM."""
        if not self.instance:
            return
        self.__run_vagrant_command('halt')

    def delete(self) -> None:
        """Deletes the vagrant VM and cleans the environment."""
        if not self.instance:
            return
        self.__run_vagrant_command('destroy -f')
        self.working_dir.rmdir()
        self.inventory = None
        self.instance = None

    def status(self) -> str:
        """Checks the status of the vagrant VM.

        Returns:
            str: The status of the instance.
        """
        if not self.instance:
            return
        self.__run_vagrant_command('status')

    # Private methods

    def _generate_key_pair(self) -> tuple[str, str]:
        """
        Generates a new key pair and returns it.

        Returns:
            tuple(str, str): The paths to the private and public keys.

        """
        cred = VagrantCredential(self.working_dir, self.name)
        private, public = cred.generate_key()
        return {'private': private, 'public': public}

    # Internal methods

    def __parse_inventory(self) -> Inventory:
        """Parses the inventory info and returns it.

        Returns:
            Inventory: The ansible inventory of the instance.
        """
        inventory = {}
        private_key = self.key_pair.get('private')
        ssh_config = self.__run_vagrant_command('ssh-config')
        patterns = {'ansible_hostname': r'HostName (.*)',
                    'ansible_user': r'User (.*)',
                    'ansible_port': r'Port (.*)'}
        # Parse the inventory.
        inventory['ansible_ssh_private_key_file'] = private_key
        for key, pattern in patterns.items():
            match = re.search(pattern, ssh_config)
            if match:
                inventory[key] = match.group(1)
            else:
                raise ValueError(f"Couldn't find {key} in vagrant ssh-config")

        return Inventory(**inventory)

    def __parse_config(self) -> VagrantConfig:
        """Parses the config and returns it.

        Returns:
            VagrantConfig: The vagrant VM configuration.
        """
        config = {}
        composite_name = self.instance_params.composite_name
        roles = self._get_role_specs()
        os_specs = self._get_os_specs()
        # Parse the configuration.
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

    def __generate_instance(self) -> Instance:
        """Generates a new instance.

        Returns:
            Instance: The instance specifications.

        """
        instance = Instance(name=self.name,
                            params=self.instance_params,
                            path=self.working_dir,
                            provider='vagrant',
                            credential=self.key_pair.get('private'),
                            connection_info=None,
                            provider_config=self.config)
        return instance

    def __generate_instance_id(self, prefix: str = "VAGRANT") -> str:
        """
        Generates a random instance id with the given prefix.

        Args:
            prefix (str): The prefix for the instance id. Defaults to "VAGRANT".

        Returns:
            str: The instance id.

        """
        return f"{prefix}-{uuid.uuid4()}".upper()

    def __run_vagrant_command(self, command: str) -> str:
        """
        Runs a Vagrant command and returns its output.

        Args:
            command (str): The vagrant command to run.

        Returns:
            str: The output of the command.
        """
        output = subprocess.run(["vagrant", command],
                                cwd=self.base_dir,
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return output.stdout.decode("utf-8")

    def __render_vagrantfile(self) -> str:
        """
        Renders the Vagrantfile template and returns it.

        Returns:
            str: The rendered Vagrantfile.

        """
        public_key = self.key_pair.get('public')
        template_path = TEMPLATES_DIR / 'vagrant'
        template_loader = jinja2.FileSystemLoader(searchpath=template_path)
        template_env = jinja2.Environment(loader=template_loader)
        loaded_template = template_env.get_template(template_path)

        return loaded_template.render(config=self.config, credential=public_key)

    def __save_vagrantfile(self, vagrantfile: str) -> None:
        """
        Saves the Vagrantfile to disk.

        Args:
            vagrantfile (str): The Vagrantfile to save.

        """
        with open(self.working_dir / 'Vagrantfile', 'w') as f:
            f.write(vagrantfile)
