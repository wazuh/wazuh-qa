from pathlib import Path
from abc import ABC, abstractmethod

import yaml

# from ..credentials.base import Credentials
from ..models import Instance, InstanceParams, Inventory, ProviderConfig

TEMPLATES_DIR = Path(__file__).parent / 'templates'
SPECS_DIR = Path(__file__).parent / 'specs'
OS_PATH = SPECS_DIR / 'os.yml'
ROLES_PATH = SPECS_DIR / 'roles.yml'


class Provider(ABC):

    def __init__(self, base_dir: Path | str, name: str, instance_params: InstanceParams):
        self.working_dir = Path(base_dir, str(name))
        self.name = str(name)
        self.instance_params = InstanceParams(**instance_params)
        self.key_pair = self._generate_key_pair()

        self.config: ProviderConfig = None
        self.instance: Instance = None
        self.inventory: Inventory = None

    @abstractmethod
    def create(self, **kwargs) -> Instance:
        raise NotImplementedError()

    @abstractmethod
    def start(self):
        raise NotImplementedError()

    @abstractmethod
    def stop(self):
        raise NotImplementedError()

    @abstractmethod
    def delete(self):
        raise NotImplementedError()

    @abstractmethod
    def status(self):
        raise NotImplementedError()

    @abstractmethod
    def _generate_key_pair(self):
        raise NotImplementedError()

    def _get_os_specs(self, provider: str) -> dict:
        with open(OS_PATH, "r") as f:
            return yaml.safe_load(f).get(provider)

    def _get_role_specs(self, provider: str) -> dict:
        with open(ROLES_PATH, "r") as f:
            return yaml.safe_load(f).get(provider)
