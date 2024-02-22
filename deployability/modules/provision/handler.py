from pathlib import Path

from modules.provision.models import ComponentInfo
from modules.provision.utils import logger


class ProvisionHandler:
    """
    Class to define how the component provisioning should be handled.

    Attributes:
        action (str): The action to be executed.
        method (str): The provision method to be executed.
        component_info (ComponentInfo): The component information.
        templates_path (str): The path to the templates.
        templates_order (list[str]): The order of the templates to be executed.
        variables_dict (dict): The variables to be used to render the templates.
    """
    _base_templates_path = Path(__file__).parent / 'playbooks'
    _actions = ['install', 'uninstall']
    _methods = ['package', 'aio', 'dependencies', 'sources']

    def __init__(self, component_info: ComponentInfo, action: str, method: str) -> None:
        """
        Initialize the component type.

        Args:
            component_info (ComponentInfo): The component information.
            action (str): The action to be executed.
            method (str): The provision method to be executed.
        """
        if not action in self._actions:
            raise ValueError(f"Unsupported action: {action}")
        if not method in self._methods:
            raise ValueError(f"Unsupported method: {method}")
        if not "wazuh" in component_info.component and method.lower() == 'aio':
            raise ValueError(f"AIO actions is only supported for Wazuh components.")

        # We cant uninstall from sources.
        if action == "uninstall" and method.lower() == "sources":
            logger.debug(f"Uninstall from sources not supported. Using package.")
            method = "package"

        self.action = action.lower()
        self.method = method.lower()
        self.component_info = component_info
        self.templates_path = self._get_templates_path()
        self.templates_order = self._get_templates_order()
        self.variables_dict = self._generate_dict()

    def _get_templates_path(self) -> str:
        """
        Get the path to the templates.

        Returns:
            str: The path to the templates.
        """
        # If the component is wazuh, we need to change the templates path.
        if "wazuh" in self.component_info.component:
            self._base_templates_path = f'{self._base_templates_path}/wazuh'

        return f"{self._base_templates_path}/{self.method}/{self.action}"

    def _get_templates_order(self) -> list[str]:
        """
        Get the order of the templates to be executed.

        Returns:
            list[str]: List of templates to be executed.
        """
        if self.method == 'package' and self.action == "install":
            return ["set_repo.j2", "install.j2", "register.j2", "service.j2"]
        elif self.method == 'aio':
            return ["download.j2", f"{self.action}.j2"]

        return []

    def _generate_dict(self) -> dict:
        """
        Generate the dictionary with the variables to be used to render the templates.

        Returns:
            dict: The variables to be used to render the templates.
        """
        variables = {
            'component': self.component_info.component,
            'version': self.component_info.version,
            'type': self.component_info.type,
            'dependencies': self.component_info.dependencies or None,
            'templates_path': self.templates_path,
            'templates_order': self.templates_order or None
        }

        return variables
