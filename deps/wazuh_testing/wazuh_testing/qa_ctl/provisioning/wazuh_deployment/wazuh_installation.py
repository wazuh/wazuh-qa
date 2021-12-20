from abc import ABC, abstractmethod

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask


class WazuhInstallation(ABC):
    """Install a Wazuh instance set from the configuration file

    Args:
        wazuh_target (string): Type of the wazuh installation desired (manager or agent).
        installation_files_path (string): Path where the Wazuh instalation files are located.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.

    Attributes:
        wazuh_target (string): Type of the wazuh installation desired (manager or agent).
        installation_files_path (string): Path where the wazuh installation files are located.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
    """
    def __init__(self, wazuh_target, installation_files_path, qa_ctl_configuration):
        self.wazuh_target = wazuh_target
        self.installation_files_path = installation_files_path
        self.qa_ctl_configuration = qa_ctl_configuration
        super().__init__()

    @abstractmethod
    def download_installation_files(self, inventory_file_path, ansible_tasks, hosts='all'):
        """Download the installation files of Wazuh  by creating an ansible playbook and launching it

        Args:
            inventory_file_path (string): path where the instalation files are going to be stored
            ansible_tasks (ansible object): ansible instance with already provided tasks to run
            hosts (string): Parameter set to `all` by default
        """
        create_path_task_unix = AnsibleTask({
            'name': f"Create {self.installation_files_path} path (Unix)",
            'file': {'path': self.installation_files_path, 'state': 'directory'},
            'when': 'ansible_system != "Win32NT"'
        })

        create_path_task_windows = AnsibleTask({
            'name': f"Create {self.installation_files_path} path (Windows)",
            'win_file': {'path': self.installation_files_path, 'state': 'directory'},
            'when': 'ansible_system == "Win32NT"'
        })

        # Add path creation task at the beggining of the playbook
        ansible_tasks.insert(0, create_path_task_unix)
        ansible_tasks.insert(1, create_path_task_windows)
        playbook_parameters = {'hosts': hosts, 'gather_facts': True, 'tasks_list': ansible_tasks}

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters,
                                          output=self.qa_ctl_configuration.ansible_output)
