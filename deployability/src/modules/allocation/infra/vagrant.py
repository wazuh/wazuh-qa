
import fnmatch
import uuid

from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from .generic import TEMPLATES_DIR, Provider, CredentialsKeyPair, InstanceDefinition, InstanceParams, ProviderConfig
from .handlers.vagrant import VagrantHandler


class VagrantConfig(ProviderConfig):
    id: str
    cpu: int
    memory: int
    ip: str
    box: str
    box_version: str


class VagrantProvider(Provider):
    provider_name = 'vagrant'

    def __init__(self):
        super().__init__()

    def create_instance(self, working_dir: str | Path, params: InstanceParams, credentials: CredentialsKeyPair) -> None:
        if not isinstance(params, InstanceParams):
            params = InstanceParams(**params)
        if not isinstance(credentials, CredentialsKeyPair):
            credentials = CredentialsKeyPair(**credentials)
        # Set the working directory and create it if needed.
        self.working_dir = Path(working_dir)
        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)
        # Get the config and the instance definitions.
        config = self.__parse_config(params.composite_name, params.role)
        vagrantfile = self.__render_vagrantfile(config, credentials)
        # Instanciate the handler and start the VM.
        self._handler = VagrantHandler(self.working_dir, vagrantfile)
        self.instance = InstanceDefinition(name=params.name,
                                           params=params,
                                           path=str(self.working_dir),
                                           provider=self.provider_name,
                                           credentials=credentials,
                                           provider_config=config)

    def load_instance(self, instance: InstanceDefinition) -> None:
        if not isinstance(instance, InstanceDefinition):
            instance = InstanceDefinition(**instance)
        if not instance.provider == self.provider_name:
            raise Exception(f"Instance provider is not {self.provider_name}")
        # Set the working directory.
        self.working_dir = Path(instance.path)
        if not self.working_dir.exists():
            raise Exception(f"Instance path {self.working_dir} does not exist")
        # Instanciate the handler and start the VM.
        self._handler = VagrantHandler(self.working_dir)
        if not self._handler.vagrantfile_defined:
            raise Exception("Vagrantfile not defined in the instance path")
        self.instance = instance

    def initialize(self) -> None:
        if not self.instance:
            raise Exception("Instance not created nor loaded")
        self._handler.start()
        # Set the connection info and instance.
        self.connection_info = self._handler.get_ssh_config()
        self.connection_info.private_key = self.instance.credentials.private_key

    def start(self) -> None:
        self._handler.start()

    def stop(self) -> None:
        self._handler.stop()

    def delete(self) -> None:
        self._handler.delete()
        self.instance = None
        self.connection_info = None

    def status(self) -> str:
        if not self.instance:
            return self._NOT_CREATED
        if 'running' in self._handler.status():
            return self._RUNNING
        return self._STOPPED

    def __render_vagrantfile(self, credentials: CredentialsKeyPair) -> str:
        """
        Renders the Vagrantfile template and returns it.

        Returns:
            str: The rendered Vagrantfile.

        """
        public_key = credentials.public_key
        environment = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        template = environment.get_template("vagrant.j2")
        return template.render(config=self._config, credential=public_key)

    def __parse_config(self, composite_name, role) -> VagrantConfig:
        """Parses the config and returns it.

        Returns:
            VagrantConfig: The vagrant VM configuration.
        """
        config = {}
        # composite_name = self.instance_params.composite_name
        roles = self._get_role_specs()
        os_specs = self._get_os_specs()
        # Parse the configuration.
        config['id'] = str(self.__generate_instance_id())
        config['box'] = os_specs[composite_name]['box']
        config['box_version'] = os_specs[composite_name]['box_version']
        for pattern, specs in roles[role].items():
            if fnmatch(composite_name, pattern):
                config['cpu'] = specs['cpu']
                config['memory'] = specs['memory']
                config['ip'] = specs['ip']
                break
        return VagrantConfig(**config)

    def __generate_instance_id(self, prefix: str = "VAGRANT") -> str:
        """
        Generates a random instance id with the given prefix.

        Args:
            prefix (str): The prefix for the instance id. Defaults to "VAGRANT".

        Returns:
            str: The instance id.

        """
        return f"{prefix}-{uuid.uuid4()}".upper()
