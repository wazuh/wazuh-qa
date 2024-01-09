from modules.generic import Ansible
from abc import ABC, abstractmethod

class Install(ABC):

  def __init__(self, ansible_data, component_information):
    self.ansible = Ansible(ansible_data)
    self.install_type = component_information.get('install_type')

    provision_template_path = ''

    match self.install_type:
      case "package":
        provision_template_path = 'provision/wazuh/package'
      case "aio":
        provision_template_path = 'provision/wazuh/aio'
      case "deps":
        provision_template_path = 'provision/deps'
      case _ :
        provision_template_path = 'provision/generic'

    component_information["templates_path"] = provision_template_path

    self.component_information = component_information

  @abstractmethod
  def install_component(self, ansible_data, playbooks_variables):
    """
    Install component on host.

    Args:
        ansible_data: Data with the ansible configuration.
        info_component_install: Data with the installation configuration.
    """
    pass

  @abstractmethod
  def set_playbooks_variables(self, install_info):
    """
    Set extra variables for the installation.

    Args:
        install_info: Data with the installation configuration.
    """
    pass

class InstallComponent(Install):

  def install_component(self):
    """
    Install component on host.

    Args:
        ansible_data: Data with the ansible configuration.
        info_component_install: Data with the installation configuration.
    """
    status = {}

    #vars = self.set_playbooks_variables(playbooks_variables)

    tasks = self.ansible.render_playbooks(self.component_information)

    playbook = {
      'hosts': self.ansible.ansible_host,
      'become': True,
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
    variables_values.update({"component": self.component_information.get('component')})

    if self.component_information.get('manager_ip'):
      variables_values.update({"manager_ip": self.component_information.get('manager_ip')})

    if "aio" in self.install_type:
      variables_values.update({
        "version": self.component_information.get('version'),
        "name": self.component_information.get('component'),
        "component": self.component_information.get('component')})

    return variables_values