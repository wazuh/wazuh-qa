from modules.generic import Ansible

from modules.provision.component_type import Package, AIO, Generic, Dependencies
from modules.provision.models import ComponentInfo
from modules.provision.utils import logger

class Action:
    """
    Class to define the action.

    Attributes:
        component (Package | AIO | Generic | Dependencies): The component to execute.
        ansible (Ansible): The Ansible instance.
    """

    def __init__(self, action: str, component_info: ComponentInfo, ansible_data: dict) -> None:
        """
        Initialize the action.

        Args:
            action (str): The action to execute.
            component_info (ComponentInfo): The component information.
            ansible_data (dict): The Ansible data.
        """
        component_info = ComponentInfo(**dict(component_info))
        action_type = component_info.type

        if action_type == "package":
            self.component = Package(component_info, action)
        elif action_type == "aio":
            self.component = AIO(component_info, action)
        elif action_type == "generic":
            self.component = Generic(component_info, action)
        elif action_type == "dependencies":
            self.component = Dependencies(component_info, action)
        else:
            raise ValueError(f"Unsupported action_type: {action_type}")

        self.ansible = Ansible(ansible_data)

    def execute(self) -> dict:
        """
        Execute the action for the component.

        Returns:
            dict: The status of the executed action.
        """
        status = {}

        ansible_task = [{
            'name': 'Capture ansible_os_family',
            'set_fact': {
                'ansible_os_family': "{{ ansible_facts['distribution_file_variety'] }}",
                'cacheable': 'yes'
            }
        }]

        playbook = {
            'hosts': self.ansible.ansible_data.ansible_host,
            'become': True,
            'gather_facts': True,
            'tasks': ansible_task
        }
        status = self.ansible.run_playbook(playbook)

        self.component.variables_dict['ansible_os_family'] = status.get_fact_cache(host=self.ansible.ansible_data.ansible_host)['ansible_os_family']

        logger.info(f"Executing {self.component.type} for {self.component.component}")

        tasks = self.ansible.render_playbooks(self.component.variables_dict)
        playbook['tasks'] = tasks

        status = self.ansible.run_playbook(playbook)

        return status
