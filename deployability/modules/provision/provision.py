# Description: Provision module for Wazuh deployability
from pathlib import Path

from modules.generic.utils import Utils
from modules.provision.actions import Action
from modules.provision.utils import logger
from modules.provision.models import InputPayload, ComponentInfo
from modules.provision.provision_module import ProvisionModule


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

        self.action = 'install' if payload.install else 'uninstall'
        self.components = self.get_components(payload)
        self.ansible_data = self.__load_ansible_data(payload.inventory)

    def run(self) -> None:
        """
        Run the provision.
        """
        logger.info(f'Initiating provisionment.')
        self.install_host_dependencies()

        logger.debug(f'Running action {self.action} for components: {self.components}')
        for component in self.components:
            try:
                logger.info(f'Provisioning "{component.component}"...')
                self.__provision(component)
                logger.info(f'Provision of "{component.component}" complete successfully.')
            except Exception as e:
                logger.error(f'Error while provisioning "{component.component}": {e}')
                raise
        logger.info('All components provisioned successfully.')
        logger.debug(f'Provision summary: {self.summary}')

    def get_components(self, payload: InputPayload) -> list[ComponentInfo]:
        """
        Validate the component and adds its dependency IP if required.

        Args:
            payload (InputPayload): Payload with the provision information.

        Returns:
            list[ComponentInfo]: List of components with the dependency IP.
        """
        components = payload.install or payload.uninstall
        # Check each component and add the dependency IP if required
        for component in components:
            if not component.component == 'wazuh-agent':
                continue
            elif not payload.manager_ip:
                raise ValueError('Dependency IP is required to install Wazuh Agent.')
            # Add the dependency IP to the component
            logger.debug(f"Setting component dependency IP: {payload.manager_ip}")
            component.manager_ip = payload.manager_ip
        return components

    def install_host_dependencies(self) -> dict:
        """
        Install python dependencies on the host.

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

    def __provision(self, component: ComponentInfo) -> None:
        """
        Provision the components.

        Args:
            component (ComponentInfo): Component to provision.
        """
        action = Action(self.action, component, self.ansible_data)
        status = action.execute()
        self.update_status(status)

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
