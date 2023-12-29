import uuid
import yaml

from abc import ABC, abstractmethod
from pathlib import Path
from pydantic import BaseModel, Field, field_validator

from modules.allocation.instances.generic import ConnectionInfo, Instance
from modules.allocation.credentials.generic import Credentials

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
    provider: str = Field(..., description='Provider to use.')
    size: str = Field(..., description='Size of the instance.')
    composite_name: str = Field(..., description='Composite name of the instance.')
    custom_credentials: str | None = Field(default=None, description='Path to the custom credentials file.')

    @field_validator('custom_credentials')
    @classmethod
    def check_credentials_exists(cls, v: str) -> str | None:
        if not v:
            return None
        path = Path(v)
        if not path.exists() or not path.is_file():
            raise ValueError(f"Invalid credentials path: {path}")
        return v


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
    def create_instance(self, base_dir: Path, params: InstanceParams, credentials: Credentials = None) -> Instance:
        """Creates a new instance."""
        pass

    @abstractmethod
    def load_instance(self, instance_dir: str | Path, identifier: str, credentials: Credentials = None) -> Instance:
        """Loads an existing instance."""
        pass
    
    @abstractmethod
    def destroy_instance(self, instance_dir: str | Path, identifier: str) -> None:
        """Destroys an existing instance."""
        pass

    @staticmethod
    def _generate_instance_id(prefix: str) -> str:
        """
        Generates a random instance id with the given prefix.

        Args:
            prefix (str): The prefix for the instance id.

        Returns:
            str: The instance id.

        """
        return f"{prefix}-{uuid.uuid4()}".upper()

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
    def _get_misc_specs(cls) -> dict:
        """
        Gets the miscellaneous specifications for the provider.

        Returns:
            dict: A dict version of the misc_specs yaml.
        """
        with open(MISC_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)
