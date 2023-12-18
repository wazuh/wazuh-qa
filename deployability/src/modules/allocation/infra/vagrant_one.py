import re
import subprocess
import uuid

from fnmatch import fnmatch
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from .generic import Provider, TEMPLATES_DIR
from ..models import CredentialsKeyPair, InstanceDefinition, InstanceParams, Inventory, VagrantConfig


class VagrantProvider(Provider):
    """A class for managing Vagrant providers.

    Attributes:
        name (str): The name of the provider.
        provider_name (str): The name of the provider.
        working_dir (Path): The working directory for the provider.
        instance_params (InstanceParams): The instance parameters.
        credentials (CredentialsKeyPair): The credentials key pair paths.
        config (ProviderConfig): The provider configuration.
    """
    provider_name = 'vagrant'

    def __init__(self, base_dir: Path | str, instance_params: InstanceParams, credentials: CredentialsKeyPair) -> None:
        """Initializes the VagrantProvider object.

        Args:
            base_dir (Path): The base directory for the provider.
            credentials (CredentialsKeyPair): The credentials key pair paths.
            instance_params (InstanceParams): The instance parameters.
        """
        super().__init__(base_dir, instance_params, credentials)

    def create(self) -> None:
        """Creates a new vagrant VM instance."""
        if self._instance and self._inventory:
            return
        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)

        # Get the config and the instance definitions.
        self._config = self.__parse_config()
        self._instance = self.__generate_instance()
        # Render and write Vagrantfile
        vagrantfile = self.__render_vagrantfile()
        self.vagrantfile = self.__save_vagrantfile(vagrantfile)
        # Start the VM and parse the inventory.
        self.__run_vagrant_command('up')
        self._inventory = self.__parse_inventory()

    def start(self) -> None:
        """Starts the vagrant VM."""
        if not self._instance:
            return
        self.__run_vagrant_command('up')

    def stop(self) -> None:
        """Stops the vagrant VM."""
        if not self._instance:
            return
        self.__run_vagrant_command('halt')

    def delete(self) -> None:
        """Deletes the vagrant VM and cleans the environment."""
        if not self._instance:
            return
        self.__run_vagrant_command('destroy -f')
        self.working_dir.rmdir()
        self._inventory = None
        self._instance = None

    def status(self) -> str:
        """Checks the status of the vagrant VM.

        Returns:
            str: The status of the instance.
        """
        if not self._instance:
            return
        output = self.__run_vagrant_command('status')
        return self.__parse_vagrant_status(output)

    def get_instance_info(self) -> InstanceDefinition:
        """Returns the instance information.

        Returns:
            InstanceDefinition: The instance information.
        """
        return self._instance

    def get_inventory(self) -> Inventory:
        """Returns the inventory.

        Returns:
            Inventory: The inventory.
        """
        return self._inventory

    # Internal methods

    def __parse_inventory(self) -> Inventory:
        """Parses the inventory info and returns it.

        Returns:
            Inventory: The ansible inventory of the instance.
        """
        inventory = {}
        private_key = self.credentials.private_key
        ssh_config = self.__run_vagrant_command('ssh-config')
        patterns = {'ansible_hostname': r'HostName (.*)',
                    'ansible_user': r'User (.*)',
                    'ansible_port': r'Port (.*)'}
        # Parse the inventory.
        inventory['ansible_ssh_private_key_file'] = private_key
        print(ssh_config)
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
        config['id'] = str(self.__generate_instance_id())
        config['box'] = os_specs[composite_name]['box']
        config['box_version'] = os_specs[composite_name]['box_version']
        for pattern, specs in roles[self.instance_params.role].items():
            if fnmatch(composite_name, pattern):
                config['cpu'] = specs['cpu']
                config['memory'] = specs['memory']
                config['ip'] = specs['ip']
                break
        return VagrantConfig(**config)

    def __parse_vagrant_status(self, message: str) -> str:
        lines = message.split('\n')
        for line in lines:
            if 'Current machine states:' in line:
                status_line = lines[lines.index(line) + 2]
                status = status_line.split()[1]
                return status

    def __generate_instance(self) -> InstanceDefinition:
        """Generates a new instance.

        Returns:
            InstanceDefinition: The instance specifications.

        """
        instance = InstanceDefinition(name=self.instance_params.name,
                            params=self.instance_params,
                            path=str(self.working_dir),
                            provider=self.provider_name,
                            credential=str(self.credentials.private_key),
                            connection_info=None,
                            provider_config=self._config)
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
        try:
            output = subprocess.run(["vagrant", command],
                                    cwd=self.working_dir,
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            if stderr := output.stderr.decode("utf-8"):
                print(stderr)
                print(output.stdout.decode("utf-8"))
            # logging.warning(f"Command '{command}' completed with errors:\n{stderr}")

            return output.stdout.decode("utf-8")

        except subprocess.CalledProcessError as e:
            print(e)
            # logging.error(f"Command '{command}' failed with error {e.returncode}:\n{e.output.decode('utf-8')}")
            return None

    def __render_vagrantfile(self) -> str:
        """
        Renders the Vagrantfile template and returns it.

        Returns:
            str: The rendered Vagrantfile.

        """
        public_key = self.credentials.public_key
        environment = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        template = environment.get_template("vagrant.j2")

        return template.render(config=self._config, credential=public_key)

    def __save_vagrantfile(self, vagrantfile: str) -> None:
        """
        Saves the Vagrantfile to disk.

        Args:
            vagrantfile (str): The Vagrantfile to save.

        """
        vagrantfile_path = self.working_dir / 'Vagrantfile'
        with open(vagrantfile_path, 'w') as f:
            f.write(vagrantfile)
        return vagrantfile_path
