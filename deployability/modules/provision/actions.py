from modules.generic import Ansible
from .componentType import Package, AIO, Generic, Dependencies

class Action:
    """
    Class to define the action.
    """
    def __init__(self, action, component_info, ansible_data):
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

    def execute(self):
        """
        Execute the action.
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

        tasks = self.ansible.render_playbooks(self.component.variables_dict)
        playbook['tasks'] = tasks

        status = self.ansible.run_playbook(playbook)

        return status

    def set_playbooks_variables(self, vars):
        """
        Method to set the playbooks extra variables.
        """
        pass
