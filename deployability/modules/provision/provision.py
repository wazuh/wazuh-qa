# Description: Provision module for Wazuh deployability
from pathlib import Path

from modules.generic.utils import Utils
from modules.provision.actions import Action
from modules.provision.utils import logger
from modules.provision.models import InputPayload, ComponentInfo
from modules.provision.provisionModule import ProvisionModule


PATH_BASE_DIR = Path(__file__).parents[2]


class Provision(ProvisionModule):
    """
    Provision class to install and uninstall components.

    Attributes:
        components (list[ComponentInfo]): List of components to install or uninstall.
        ansible_data (dict): Ansible data to render the playbooks.
        summary (dict): Summary of the provision.
    """

    def __init__(self, payload: InputPayload):
        """
        Initialize the provision.

        Args:
            payload (InputPayload): Payload with the provision information.
        """
        self.summary = {}

        if payload.install:
            self.components = payload.install
            self.action = "install"
        if payload.uninstall:
            self.components = payload.uninstall
            self.action = "uninstall"

        self.validate_component_ip(self.components, payload.manager_ip)
        self.ansible_data = self.__load_ansible_data(payload.inventory)

    def run(self) -> None:
        """
        Run the provision.
        """
        logger.debug(f'Initiating provision "{self.action}" for {self.components}.')
        self.install_host_dependencies()

        for item in self.components:
            action = Action(self.action, item, self.ansible_data)
            status = action.execute()
            self.update_status(status)

        logger.info('Provision complete successfully.')
        logger.debug(f'Provision summary: {self.summary}')

    def validate_component_ip(self, components: list[ComponentInfo], ip: str) -> None:
        if not ip:
            return
        for component in components:
            if component.component == 'wazuh-agent':
                logger.debug(f"Setting component dependency IP: {ip}")
                component.manager_ip = ip

    def install_host_dependencies(self) -> dict:
        """
        Install python dependencies on host.

        Returns:
            dict: Status of the installation.
        """
        deps_path = PATH_BASE_DIR / "deps" / "remote_requirements.txt"
        package = ComponentInfo(component=str(deps_path), type="dependencies")
        logger.debug(f"Installing dependencies on guests: {package}")
        action_class = Action("install", package, self.ansible_data)
        status = action_class.execute()

        return status

    def update_status(self, status: dict) -> None:
        """
        Update the status of the provision.

        Args:
            status (dict): The status of the executed action.
        """
        self.summary.update(status.stats)

    def __load_ansible_data(self, inventory: str | Path) -> dict:
        """
        Load the ansible data from the inventory file.

        Args:
            inventory (str | Path): Path to the inventory file.

        Returns:
            dict: Ansible data to render the playbooks.
        """
        try:
            return Utils.load_from_yaml(inventory)
        except FileNotFoundError:
            logger.error(f'Inventory file "{inventory}" not found.')
            raise
        except Exception as e:
            logger.error(f'Error loading inventory file "{inventory}": {e}')
            raise
