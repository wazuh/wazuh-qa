import os
import yaml
from tempfile import gettempdir

from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class AnsiblePlaybook():
    """Class to create playbook file with a custom tasks list

    Args:
        name (str): Playbook name.
        tasks_list (list(AnsibleTask)): List of ansible tasks that will be launched.
        playbook_file_path (str): Path where the playbook will be stored.
        hosts (str): Group of hosts to which send the tasks.
        gather_facts (bool): Allow or denied the gather_facts fetch
        become (bool): Allo or denied privilege escalation.
        playbook_vars (dict): Variables for playbook
        generate_file (bool): If True, write playbook in file.

    Attributes:
        name (str): Playbook name.
        tasks_list (list(AnsibleTask)): List of ansible tasks that will be launched.
        playbook_file_path (str): Path where the playbook will be stored.
        hosts (str): Group of hosts to which send the tasks.
        gather_facts (bool): Allow or denied the gather_facts fetch
        become (bool): Allo or denied privilege escalation.
        playbook_vars (dict): Variables for playbook
        generate_file (bool): If True, write playbook in file.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, name='generic_playbook', tasks_list=None, playbook_file_path=None, hosts='all',
                 gather_facts=False, ignore_errors=False, become=False, playbook_vars=None, generate_file=True):
        self.name = name
        self.hosts = hosts
        self.gather_facts = gather_facts
        self.tasks_list = tasks_list
        self.ignore_errors = ignore_errors
        self.become = become
        self.playbook_vars = playbook_vars
        self.playbook_file_path = playbook_file_path if playbook_file_path else \
            f"{gettempdir()}/wazuh_qa_ctl/{get_current_timestamp()}.yaml"
        if generate_file:
            self.write_playbook_to_file()

    def __str__(self):
        """Define how the class object is to be displayed."""
        playbook = {'hosts': self.hosts, 'gather_facts': self.gather_facts, 'become': self.become,
                    'ignore_errors': self.ignore_errors}

        if self.playbook_vars is not None:
            playbook['vars'] = self.playbook_vars

        if self.tasks_list is not None:
            playbook['tasks'] = []
            for ansible_task in self.tasks_list:
                playbook['tasks'].append(ansible_task.items)

        playbook_string = yaml.dump([playbook], default_flow_style=False, sort_keys=False)

        return playbook_string

    def write_playbook_to_file(self):
        """Write the ansible playbook data in a file"""
        if not os.path.exists(os.path.dirname(self.playbook_file_path)):
            os.makedirs(os.path.dirname(self.playbook_file_path))

        with open(self.playbook_file_path, 'w+') as file:
            file.write(self.__str__())

    def delete_playbook_file(self):
        """Delete the existing playbook file"""
        if os.path.exists(self.playbook_file_path):
            os.remove(self.playbook_file_path)
            AnsiblePlaybook.LOGGER.debug(f"{self.playbook_file_path} playbook file was deleted")
