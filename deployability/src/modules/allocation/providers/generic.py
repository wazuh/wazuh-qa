import yaml

from abc import ABC, abstractmethod
from pathlib import Path
from pydantic import BaseModel

from .instances.generic import ConnectionInfo, Instance

# Paths to the templates and specs directories.
ROOT_DIR = Path(__file__).parent / 'static'
TEMPLATES_DIR = ROOT_DIR / 'templates'
SPECS_DIR = ROOT_DIR / 'specs'
OS_PATH = SPECS_DIR / 'os.yml'
SIZE_PATH = SPECS_DIR / 'size.yml'
MISC_PATH = SPECS_DIR / 'misc.yml'


class ProviderConfig(BaseModel):
    pass


class InstanceParams(BaseModel):
    name: str
    provider: str
    size: str
    alias: str
    composite_name: str
    custom_credentials: str | Path = None


# class InstanceDefinition(BaseModel):
#     name: str
#     params: InstanceParams
#     path: str
#     provider: str
#     credentials: Path | str
#     provider_config: ProviderConfig


class Provider(ABC):
    """An abstract base class for providers.

    Attributes:
        provider_name (str): The name of the provider.

    """
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """The name of the provider."""
        pass

    @abstractmethod
    def create_instance(self, **kwargs) -> Instance:
        """Creates a new instance."""
        pass

    @abstractmethod
    def load_instance(self, **kwargs) -> Instance:
        """Loads an existing instance."""
        pass

    @classmethod
    def _get_os_specs(cls) -> dict:
        """
        Gets the OS specifications for the provider.

        Returns:
            dict: A dict version of the os_specs yaml.
        """
        with open(OS_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)

    @classmethod
    def _get_size_specs(cls) -> dict:
        """
        Gets the size specifications for the provider.

        Returns:
            dict: A dict version of the size_specs yaml.
        """
        with open(SIZE_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)
    
    @classmethod
    def get_misc_specs(cls) -> dict:
        """
        Gets the miscellaneous specifications for the provider.

        Returns:
            dict: A dict version of the misc_specs yaml.
        """
        with open(MISC_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)
