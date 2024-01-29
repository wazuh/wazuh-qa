import platform
import socket

from jinja2 import Environment, FileSystemLoader
from pathlib import Path

from modules.allocation.generic import Provider
from modules.allocation.generic.models import CreationPayload
from .credentials import VagrantCredentials
from .instance import VagrantInstance
from .models import VagrantConfig


class VagrantProvider(Provider):
    """
    The VagrantProvider class is a provider for managing Vagrant instances.
    It inherits from the generic Provider class.

    Attributes:
        provider_name (str): Name of the provider ('vagrant').
    """
    provider_name = 'vagrant'

    @classmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload, config: VagrantConfig = None) -> VagrantInstance:
        """
        Creates a Vagrant instance.

        Args:
            base_dir (Path): The base directory for the instance.
            params (CreationPayload): The parameters for instance creation.
            config (VagrantConfig, optional): The configuration for the instance. Defaults to None.

        Returns:
            VagrantInstance: The created Vagrant instance.
        """
        instance_id = cls._generate_instance_id(cls.provider_name)
        # Create the instance directory.
        instance_dir = base_dir / instance_id
        instance_dir.mkdir(parents=True, exist_ok=True)
        # Generate the credentials.
        credentials = VagrantCredentials()
        credentials.generate(instance_dir, 'instance_key')
        if not config:
            # Parse the config if it is not provided.
            config = cls.__parse_config(params, credentials)
        # Create the Vagrantfile.
        cls.__create_vagrantfile(instance_dir, config)
        return VagrantInstance(instance_dir, instance_id, credentials)

    @staticmethod
    def _load_instance(instance_dir: Path, identifier: str) -> VagrantInstance:
        """
        Loads a Vagrant instance.

        Args:
            instance_dir (Path): The directory of the instance.
            identifier (str): The identifier of the instance.

        Returns:
            VagrantInstance: The loaded Vagrant instance.
        """
        return VagrantInstance(instance_dir, identifier)

    @staticmethod
    def _destroy_instance(instance_dir: Path, identifier: str) -> None:
        """
        Destroys a Vagrant instance.

        Args:
            instance_dir (Path): The directory of the instance.
            identifier (str): The identifier of the instance.

        Returns:
            None
        """
        instance = VagrantInstance(instance_dir, identifier)
        instance.delete()

    @classmethod
    def __create_vagrantfile(cls, instance_dir: Path, config: VagrantConfig) -> None:
        """
        Creates a Vagrantfile in the instance directory.

        Args:
            instance_dir (Path): The directory to create the Vagrantfile in.
            config (VagrantConfig): The configuration for the Vagrantfile.

        Returns:
            None
        """
        if 'win' in platform.system().lower():
            # Add dobule backslashes for windows.
            config.public_key = config.public_key.replace('\\', '\\\\')
        content = cls.__render_vagrantfile(config)
        with open(instance_dir / 'Vagrantfile', 'w') as f:
            f.write(content)

    @classmethod
    def __render_vagrantfile(cls, config: VagrantConfig) -> str:
        """
        Renders a Vagrantfile template.

        Args:
            config (VagrantConfig): The configuration for the Vagrantfile.

        Returns:
            str: The rendered Vagrantfile.
        """
        environment = Environment(loader=FileSystemLoader(cls.TEMPLATES_DIR))
        template = environment.get_template("vagrant.j2")
        return template.render(config=config)

    @classmethod
    def __parse_config(cls, params: CreationPayload, credentials: VagrantCredentials) -> VagrantConfig:
        """
        Parses the configuration for a Vagrant instance.

        Args:
            params (CreationPayload): The parameters for instance creation.
            credentials (VagrantCredentials): The credentials for the instance.

        Returns:
            VagrantConfig: The parsed configuration for the Vagrant instance.
        """
        config = {}
        # Get the specs from the yamls.
        size_specs = cls._get_size_specs()[params.size]
        os_specs = cls._get_os_specs()[params.composite_name]
        # Parse the configuration.
        config['ip'] = cls.__get_available_ip()
        config['box'] = os_specs['box']
        config['box_version'] = os_specs['box_version']
        config['public_key'] = str(credentials.key_path.with_suffix('.pub'))
        config['cpu'] = size_specs['cpu']
        config['memory'] = size_specs['memory']

        return VagrantConfig(**config)

    @classmethod
    def __get_available_ip(cls):
        """
        Gets an available IP address.

        Returns:
            str: An available IP address.

        Raises:
            Exception: If no available IP address is found.
        """
        available_ip = None

        def check_ip(ip):
            try:
                socket.gethostbyaddr(ip)
                return False
            except socket.herror:
                return True

        for i in range(1, 255):
            ip = f"192.168.57.{i}"
            if check_ip(ip):
                available_ip = ip
                break
        if not available_ip:
            raise cls.ProvisioningError("No available IP address found.")
        return available_ip
