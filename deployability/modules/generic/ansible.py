import yaml
import ansible_runner

from pathlib import Path


class Ansible:
    def __init__(self, inventory: str | Path, path: Path = None):
        self._inventory = self._read_inventory(inventory)
        self._working_dir = Path(path) if path else None

    # Setters and Getters

    def set_inventory(self, inventory: str | Path) -> None:
        self._inventory = self._read_inventory(inventory)

    def get_inventory(self) -> dict:
        return self._inventory

    def set_working_dir(self, path) -> None:
        self._working_dir = path

    def get_working_dir(self) -> Path:
        return self._working_dir

    # Instance Methods

    # https://ansible.readthedocs.io/projects/runner/en/1.1.0/ansible_runner.html
    def run_playbook(self, playbook: str | Path = None, extravars: dict = None, verbosity: int = 1) -> dict:
        if self._working_dir:
            playbook = self._working_dir / playbook
        if not Path(playbook).exists():
            raise ValueError(f'Playbook "{playbook}" does not exist')
        # Execute the playbook.
        result = ansible_runner.run(inventory=self._inventory,
                                    playbook=str(playbook),
                                    verbosity=verbosity,
                                    extravars=extravars)
        return result

    # Internal Methods

    def _read_inventory(self, inventory: str | Path) -> dict:
        if not Path(inventory).exists():
            raise ValueError(f'Inventory file "{inventory}" does not exist')
        with open(inventory, 'r') as file:
            return yaml.safe_load(file)
