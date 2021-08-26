from abc import ABC, abstractmethod

from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_installation import WazuhInstallation


class WazuhPackage(WazuhInstallation, ABC):

    def __init__(self, version, system, wazuh_target, installation_files_path):
        self.version = version
        self.system = system
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path)

    @abstractmethod
    def download_installation_files(self, inventory_file_path, ansible_tasks, hosts='all'):
        super().download_installation_files(inventory_file_path, ansible_tasks, hosts)
