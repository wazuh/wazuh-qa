import shutil
import uuid
import yaml

from abc import ABC, abstractmethod
from pathlib import Path

from .instance import Instance
from .models import CreationPayload


class Provider(ABC):
    """An abstract base class for providers.

    Attributes:
        provider_name (str): The name of the provider.

    """

    # Paths to the templates and specs directories.
    ROOT_DIR = Path(__file__).parent.parent / 'static'
    TEMPLATES_DIR = ROOT_DIR / 'templates'
    SPECS_DIR = ROOT_DIR / 'specs'
    OS_PATH = SPECS_DIR / 'os.yml'
    SIZE_PATH = SPECS_DIR / 'size.yml'
    MISC_PATH = SPECS_DIR / 'misc.yml'

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """The name of the provider."""
        pass

    @classmethod
    def create_instance(cls, base_dir: str | Path, params: CreationPayload) -> Instance:
        params = CreationPayload(**dict(params))
        base_dir = Path(base_dir)
        return cls._create_instance(base_dir, params)


    @classmethod
    def load_instance(cls, instance_dir: str | Path, instance_id: str) -> Instance:
        instance_dir = Path(instance_dir)
        if not instance_dir.exists():
            raise Exception(f"Instance path {instance_dir} does not exist")
        return cls._load_instance(instance_dir, instance_id)

    @classmethod
    def destroy_instance(cls, instance_dir: str | Path, identifier: str) -> None:
        instance_dir = Path(instance_dir)
        cls._destroy_instance(instance_dir, identifier)
        shutil.rmtree(instance_dir, ignore_errors=True)

    @classmethod
    @abstractmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload) -> Instance:
        """Creates a new instance."""
        pass
    
    @classmethod
    @abstractmethod
    def _load_instance(cls, instance_dir: Path, identifier: str) -> Instance:
        """Loads an existing instance."""
        pass
    
    @classmethod
    @abstractmethod
    def _destroy_instance(cls, instance_dir: Path, identifier: str) -> None:
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
        with open(cls.OS_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)

    @classmethod
    def _get_size_specs(cls) -> dict:
        """
        Gets the size specifications for the provider.

        Returns:
            dict: A dict version of the size_specs yaml.
        """
        with open(cls.SIZE_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)

    @classmethod
    def _get_misc_specs(cls) -> dict:
        """
        Gets the miscellaneous specifications for the provider.

        Returns:
            dict: A dict version of the misc_specs yaml.
        """
        with open(cls.MISC_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)
