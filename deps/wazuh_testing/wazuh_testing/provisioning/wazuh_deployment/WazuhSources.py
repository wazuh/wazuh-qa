from ansible.AnsibleTask import AnsibleTask
from deployment.WazuhInstallation import WazuhInstallation
import ansible.AnsiblePlaybook


class WazuhSources(WazuhInstallation):

    def download_sources(self, inventory_path, playbook_path, hosts='all'):
        name = 'ansibleconcept',

        task_git = {'git': {'repo': self.download_target,
                    'dest': self.target_path, 'version': self.wazuh_branch}}

        ansible_tasks = [AnsibleTask(task_git)]
        ansible_playbook = ansible.AnsiblePlaybook.AnsiblePlaybook(name=name, tasks_list=ansible_tasks,
                                                                   playbook_file_path=playbook_path, hosts=hosts)

    def __init__(self, target, target_path, wazuh_branch, download_target):
        self.wazuh_branch = wazuh_branch
        self.download_target = download_target
        super().__init__(target, target_path)
