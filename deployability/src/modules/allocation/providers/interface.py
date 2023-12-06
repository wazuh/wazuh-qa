from pathlib import Path

import yaml
from ..models import InstanceParams


class ProviderInterface:
    TEMPLATES_DIR = Path(__file__).parent / 'templates'
    SPECS_DIR = Path(__file__).parent / 'specs'
    OS_PATH = SPECS_DIR / 'os.yml'
    ROLES_PATH = SPECS_DIR / 'roles.yml'

    def __init__(self, instance_params: InstanceParams):
        self.instance_params = instance_params

    def create(self):
        raise NotImplementedError()

    def start(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    def status(self):
        raise NotImplementedError()

    def get_ansible_inventory(self):
        raise NotImplementedError()

    def __get_os_specs(self, provider: str) -> dict:
        with open(self.OS_PATH, "r") as f:
            return yaml.safe_load(f).get(provider)

    def __get_role_specs(self, provider: str) -> dict:
        with open(self.ROLES_PATH, "r") as f:
            return yaml.safe_load(f).get(provider)
