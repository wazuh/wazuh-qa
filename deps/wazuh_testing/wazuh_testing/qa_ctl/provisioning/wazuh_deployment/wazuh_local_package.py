from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_package import WazuhPackage
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from pathlib import Path
import os


class WazuhLocalPackage(WazuhPackage):

    def __init__(self, wazuh_target, installation_files_path, local_package_path, version=None, system=None):
        self.local_package_path = local_package_path
        self.package_name = Path(self.local_package_path).name
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path, version=version,
                         system=system)

    def download_installation_files(self, inventory_file_path, hosts='all'):
        copy_ansible_task = AnsibleTask({'name': f"Copy {self.local_package_path} package to \
                                                   {self.installation_files_path}",
                                                 'copy': {'src': self.local_package_path,
                                                          'dest': self.installation_files_path}})
        super().download_installation_files(inventory_file_path, [copy_ansible_task], hosts)

        return os.path.join(self.installation_files_path, self.package_name)
