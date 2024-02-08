from modules.generic import Ansible
from abc import ABC, abstractmethod


class Install(ABC):
    """
    Install class used to install a component on a host.
    """

    def __init__(self, ansible_data: dict, component_information: dict) -> None:
        """
        Initialize the Install class.

        Args:
            ansible_data: Data with the ansible configuration.
            component_information: Data with the installation configuration.
        """
        self.ansible = Ansible(ansible_data)
        self.install_type = component_information.get('install_type')

        list_template_order = ''

        match self.install_type:
            case "package":
                provision_template_path = 'provision/wazuh/package'
                list_template_order = ["set_repo.j2",
                                       "install.j2", "register.j2", "service.j2"]
            case "aio":
                provision_template_path = 'provision/wazuh/aio'
                list_template_order = ["download.j2",
                                       "install.j2", "register", "service"]
            case "deps":
                provision_template_path = 'provision/deps'
            case _:
                provision_template_path = 'provision/generic'

        component_information["templates_path"] = provision_template_path
        component_information["list_template_order"] = list_template_order

        self.component_information = component_information

    @abstractmethod
    def install_component(self, ansible_data: dict, playbooks_variables: dict) -> dict:
        """
        Install component on host.

        Args:
            ansible_data: Data with the ansible configuration.
            info_component_install: Data with the installation configuration.
        """
        pass

    @abstractmethod
    def set_playbooks_variables(self, install_info: dict) -> dict:
        """
        Set extra variables for the installation.

        Args:
            install_info: Data with the installation configuration.
        """
        pass


class InstallComponent(Install):
    """
    InstallComponent class used to install a component on a host.
    """

    def install_component(self):
        """
        Install component on host.

        Args:
            ansible_data: Data with the ansible configuration.
            info_component_install: Data with the installation configuration.
        """
        status = {}

        # vars = self.set_playbooks_variables(playbooks_variables)

        tasks = self.ansible.render_playbooks(self.component_information)

        playbook = {
            'hosts': self.ansible.ansible_host,
            'become': True,
            'gather_facts': True,
            'tasks': tasks
        }

        status = self.ansible.run_playbook(playbook)

        return status

    def set_playbooks_variables(self, vars):
        """
        Set extra variables for the installation.

        Args:
            install_info: Data with the installation configuration.
        """
        variables_values = {}

        return variables_values
