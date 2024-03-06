# Description: Class to define the type of component to be provisioned
from abc import ABC, abstractmethod

from modules.provision.models import ComponentInfo


class ComponentType(ABC):
    """
    Class to define the type of component to be provisioned

    Attributes:
        component (str): The component to be provisioned.
        type (str): The type of the component.
        version (str): The version of the component.
        dependencies (str): The IPs of the component dependencies. Example: Manager's IP.
        templates_path (str): The path to the templates.
        templates_order (list[str]): The order of the templates to be executed.
    """
    templates_order: list[str]
    templates_path: str

    def __init__(self, component_info: ComponentInfo) -> None:
        """
        Initialize the component type.

        Args:
            component_info (ComponentInfo): The component information.
        """
        self.component = component_info.component
        self.type = component_info.type
        self.version = component_info.version
        self.dependencies = component_info.dependencies or None

    def get_templates_path(self, action: str):
        """
        Get the path to the templates.
        """
        pass

    @abstractmethod
    def get_templates_order(self, action: str) -> list:
        """
        Get the order of the templates to be executed.
        """
        pass

    def generate_dict(self):
        """
        Generate the dictionary with the variables to be used to render the templates.
        """
        variables = {
            'component': self.component,
            'version': self.version,
            'version': self.type,
            'dependencies': self.dependencies,
            'templates_path': self.templates_path,
            'templates_order': self.templates_order or None
        }

        return variables


class Package(ComponentType):
    """
    Class to define the type of package to be provisioned.
    """
    __TEMPLATE_BASE_PATH = 'provision/wazuh'

    def __init__(self, component_info: ComponentType, action: str) -> None:
        """
        Initialize the package component type.

        Args:
            component_info (ComponentInfo): The component information.
            action (str): The action to be executed.
        """
        super().__init__(component_info)
        self.templates_path = f'{self.__TEMPLATE_BASE_PATH}/{self.type}/{action}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action: str) -> list[str]:
        """
        Get the order of the templates to be executed.

        Args:
            action (str): The action to be executed.
        """
        if action == "install":
            return ["set_repo.j2", "install.j2", "register.j2", "service.j2"]
        return []


class AIO(ComponentType):
    """
    Class to define the type of AIO to be provisioned
    """
    __TEMPLATE_BASE_PATH = 'provision/wazuh'

    def __init__(self, component_info: ComponentType, action: str) -> None:
        """
        Initialize the AIO component type.

        Args:
            component_info (ComponentInfo): The component information.
            action (str): The action to be executed.
        """
        super().__init__(component_info)
        self.templates_path = f'{self.__TEMPLATE_BASE_PATH}/{self.type}/{action}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action: str) -> list[str]:
        return ["download.j2", f"{action}.j2"]


class Generic(ComponentType):
    """
    Class to define the type of generic component to be provisioned
    """
    __TEMPLATE_BASE_PATH = 'provision/generic'

    def __init__(self, component_info: ComponentType, action: str) -> None:
        super().__init__(component_info)
        self.templates_path = f'{self.__TEMPLATE_BASE_PATH}/{action}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action: str) -> list:
        return []


class Dependencies(ComponentType):
    """
    Class to define the type of dependencies to be provisioned
    """
    __TEMPLATE_BASE_PATH = 'provision/deps'

    def __init__(self, component_info: ComponentType, action: str) -> None:
        super().__init__(component_info)
        self.templates_path = f'{self.__TEMPLATE_BASE_PATH}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action: str) -> list:
        return []
