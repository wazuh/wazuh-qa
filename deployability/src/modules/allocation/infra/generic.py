import yaml

from abc import ABC, abstractmethod
from pathlib import Path
from pydantic import BaseModel

from ..credentials.generic import CredentialsKeyPair
from .handlers.generic import ConnectionInfo

# Paths to the templates and specs directories.
ROOT_DIR = Path(__file__).parent / 'static'
TEMPLATES_DIR = ROOT_DIR / 'templates'
SPECS_DIR = ROOT_DIR / 'specs'
OS_PATH = SPECS_DIR / 'os.yml'
ROLES_PATH = SPECS_DIR / 'roles.yml'


class ProviderConfig(BaseModel):
    pass


class InstanceParams(BaseModel):
    name: str
    role: str
    alias: str
    composite_name: str


class InstanceDefinition(BaseModel):
    name: str
    params: InstanceParams
    path: str
    provider: str
    credentials: CredentialsKeyPair
    provider_config: ProviderConfig


class Provider(ABC):
    """An abstract base class for providers.

    Attributes:
        name (str): The name of the provider.
        provider_name (str): The name of the provider.
        working_dir (Path): The working directory for the provider.
        instance_params (InstanceParams): The instance parameters.
        credentials (CredentialsKeyPair): The credentials key pair paths.
        config (ProviderConfig): The provider configuration.

    """

    _RUNNING = 'running'
    _STOPPED = 'stopped'
    _NOT_CREATED = 'not created'

    def __init__(self) -> None:
        """
        Initializes the Provider object.
        """
        self._working_dir: Path | str = None
        self._handler = None
        self.instance: InstanceDefinition = None
        self.connection_info: ConnectionInfo = None

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """The name of the provider."""
        pass

    @abstractmethod
    def create_instance(self, **kwargs) -> None:
        """Creates a new instance."""
        pass

    @abstractmethod
    def load_instance(self, instance: InstanceDefinition) -> None:
        """Loads an existing instance."""
        pass

    @abstractmethod
    def initialize(self) -> None:
        """Initializes the instance."""
        pass

    @abstractmethod
    def start(self):
        """Starts the instance."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stops the instance."""
        pass

    @abstractmethod
    def delete(self) -> None:
        """Deletes the instance."""
        pass

    @abstractmethod
    def status(self) -> str:
        """
        Checks the status of the instance.

        Returns:
            str: The status of the instance.
        """
        pass

    @abstractmethod
    def get_connection_info(self) -> ConnectionInfo:
        """
        Returns the connection info of the instance.

        Returns:
            ConnectionInfo: The instance's connection info.
        """
        pass


    def _get_os_specs(self) -> dict:
        """
        Gets the OS specifications for the provider.

        Returns:
            dict: A dict version of the os_specs yaml.
        """
        with open(OS_PATH, "r") as f:
            return yaml.safe_load(f).get(self.provider_name)

    def _get_role_specs(self) -> dict:
        """
        Gets the role specifications for the provider.

        Returns:
            dict: A dict version of the role_specs yaml.
        """
        with open(ROLES_PATH, "r") as f:
            return yaml.safe_load(f).get(self.provider_name)
