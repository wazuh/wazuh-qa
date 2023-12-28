import fnmatch
import shutil
import uuid

from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from pydantic import field_validator

from .generic import TEMPLATES_DIR, Provider, ProviderConfig, InstanceParams
from .credentials.vagrant import VagrantCredentials
from .instances.generic import ConnectionInfo
from .instances.vagrant import VagrantInstance


class VagrantConfig(ProviderConfig):
    cpu: int
    memory: int
    ip: str
    box: str
    box_version: str
    public_key: Path

    @field_validator('public_key', mode='before')
    @classmethod
    def check_public_key_exists(cls, v: Path | str) -> Path:
        path = Path(v)
        if not path.exists() or not path.is_file():
            raise ValueError(f"Invalid public key path: {path}")
        return path


class VagrantProvider(Provider):
    provider_name = 'vagrant'

    @classmethod
    def create_instance(cls, base_dir: str | Path, params: InstanceParams, credentials: VagrantCredentials = None) -> VagrantInstance:
        params = InstanceParams(**dict(params))
        base_dir = Path(base_dir)
        if credentials and not isinstance(credentials, VagrantCredentials):
            raise Exception(f"Credentials must be of type {VagrantCredentials}")
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        return cls.__create_instance(base_dir, params, credentials)

    @staticmethod
    def load_instance(instance_dir: str | Path, identifier: str, credentials: VagrantCredentials = None) -> VagrantInstance:
        instance_dir = Path(instance_dir)
        if not instance_dir.exists():
            raise Exception(f"Instance path {instance_dir} does not exist")
        if not credentials:
            credentials = VagrantCredentials()
            credentials.generate(instance_dir, 'instance_key')
        elif not isinstance(credentials, VagrantCredentials):
            raise Exception(f"Credentials must be of type {VagrantCredentials}")
        instance = VagrantInstance(instance_dir, identifier, credentials)
        return instance
    
    @classmethod
    def destroy_instance(cls, instance_dir: str | Path, identifier: str) -> None:
        instance_dir = Path(instance_dir)
        if not instance_dir.exists():
            raise Exception(f"Instance path {instance_dir} does not exist")
        instance = VagrantInstance(instance_dir, identifier)
        instance.destroy()
        shutil.rmtree(instance_dir, ignore_errors=True)

    @classmethod
    def __create_instance(cls, base_dir: Path, params: InstanceParams, credentials: VagrantCredentials = None) -> VagrantInstance:
        instance_id = cls.__generate_instance_id()
        instance_dir = base_dir / instance_id
        # Create the instance directory if it doesn't exist.
        if not instance_dir.exists():
            instance_dir.mkdir(parents=True, exist_ok=True)
        elif not instance_dir.is_dir():
            raise Exception(f"Instance path {instance_dir} is not a dir.")
        if not credentials:
            credentials = VagrantCredentials()
            credentials.generate(instance_dir, 'instance_key')

        config = cls._parse_config(params, credentials)
        cls.__create_vagrantfile(instance_dir, config)
        return VagrantInstance(instance_dir, instance_id, credentials)

    @classmethod
    def __create_vagrantfile(cls, instance_dir: Path, config: VagrantConfig) -> None:
        """
        Saves a Vagrantfile in the current working_dir.

        Args:
            instance_dir (Path): Path to the instance directory.
            config (VagrantConfig): Instance config to use in the vagrantfile.
        """
        content = cls.__render_vagrantfile(config)
        with open(instance_dir / 'Vagrantfile', 'w') as f:
            f.write(content)

    @staticmethod
    def __render_vagrantfile(config: VagrantConfig) -> str:
        """
        Renders the Vagrantfile template and returns it.

        Returns:
            str: The rendered Vagrantfile.

        """
        environment = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        template = environment.get_template("vagrant.j2")
        return template.render(config=config)

    @classmethod
    def _parse_config(cls, params: InstanceParams, credentials: VagrantCredentials) -> VagrantConfig:
        """Parses the config and returns it.

        Returns:
            VagrantConfig: The vagrant VM configuration.
        """
        config = {}

        # Get the specs from the yamls.
        size_specs = cls._get_size_specs()[params.size]
        os_specs = cls._get_os_specs()[params.composite_name]
        # Parse the configuration.
        config['box'] = os_specs['box']
        config['box_version'] = os_specs['box_version']
        config['public_key'] = credentials.key_path.with_suffix('.pub')
        config['cpu'] = size_specs['cpu']
        config['memory'] = size_specs['memory']
        config['ip'] = size_specs['ip']

        return VagrantConfig(**config)

    @staticmethod
    def __generate_instance_id(prefix: str = "VAGRANT") -> str:
        """
        Generates a random instance id with the given prefix.

        Args:
            prefix (str): The prefix for the instance id. Defaults to "VAGRANT".

        Returns:
            str: The instance id.

        """
        return f"{prefix}-{uuid.uuid4()}".upper()
