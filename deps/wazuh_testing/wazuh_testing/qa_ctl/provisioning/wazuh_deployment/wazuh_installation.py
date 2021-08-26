from abc import ABC, abstractmethod

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask


class WazuhInstallation(ABC):
    def __init__(self, wazuh_target, installation_files_path):
        self.wazuh_target = wazuh_target
        self.installation_files_path = installation_files_path
        super().__init__()

    @abstractmethod
    def download_installation_files(self, inventory_file_path, ansible_tasks, hosts='all'):
        create_path_task = AnsibleTask({'name': f"Create {self.installation_files_path} path",
                                        'file': {'path': self.installation_files_path, 'state': 'directory'}})
        # Add path creation task at the beggining of the playbook
        ansible_tasks.insert(0, create_path_task)
        playbook_parameters = {'hosts': hosts, 'tasks_list': ansible_tasks}

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters)
