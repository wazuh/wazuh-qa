from pathlib import Path
from abc import ABC, abstractmethod

import yaml

from . import OS_PATH, ROLES_PATH
from ..models import Instance, InstanceParams, Inventory, ProviderConfig


class Provider(ABC):
    """An abstract base class for providers.

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

    def __init__(self, base_dir: Path | str, name: str, instance_params: InstanceParams):
        """
        Initializes the Provider object.

        Args:
            base_dir (Path): The base directory for the provider.
            name (str): The name of the provider.
            instance_params (InstanceParams): The instance parameters.
        """
        self.working_dir = Path(base_dir, str(name))
        self.name = str(name)
        self.instance_params = InstanceParams(**instance_params)
        self.key_pair = self._generate_key_pair()

        self.config: ProviderConfig = None
        self.instance: Instance = None
        self.inventory: Inventory = None

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """The name of the provider."""
        pass

    @abstractmethod
    def create(self, **kwargs) -> Instance:
        """
        Creates a new instance.

        Returns:
            Instance: The instance specifications.
        """
        pass

    @abstractmethod
    def start(self) -> Inventory:
        """
        Starts the instance.

        Returns:
            Inventory: The ansible inventory of the instance.
        """
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
    def _generate_key_pair(self) -> tuple[str, str]:
        """
        Generates a new key pair.

        Returns:
            tuple(str, str): The paths to the private and public keys.
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
