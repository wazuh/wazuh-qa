from abc import ABC, abstractmethod
from deployment.WazuhInstallation import WazuhInstallation
from ansible.AnsiblePlaybook import AnsiblePlaybook
from ansible.AnsibleTask import AnsibleTask


class LocalPackage(WazuhInstallation):

    def download_sources(self, playbook_path, inventory_path, hosts='all'):

        ansible_task = AnsibleTask({'copy': {'src': self.package_path, 'dest': self.target_path}})

        ansible_playbook = AnsiblePlaybook(name="packages_tasks", tasks_list=[ansible_task],
                                           playbook_file_path=playbook_path, hosts=hosts)

    def __init__(self, target, target_path, package_path):
        self.package_path = package_path
        super().__init__(target=target, target_path=target_path)
