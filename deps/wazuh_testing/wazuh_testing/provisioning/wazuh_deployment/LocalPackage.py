from wazuh_testing.provisioning.wazuh_deployment.WazuhPackage import WazuhPackage
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask


class LocalPackage(WazuhPackage):

    def __init__(self, wazuh_target, installation_files_path, local_package_path, version, system):
        self.local_package_path = local_package_path
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path, version=version,
                         system=system)

    def download_installation_files(self, inventory_file_path, hosts='all'):
        copy_ansible_task = AnsibleTask({'name': f"Copy {self.local_package_path} package to \
                                                   {self.installation_files_path}",
                                                 'copy': {'src': self.local_package_path,
                                                          'dest': self.installation_files_path}})
        super().download_installation_files(inventory_file_path, [copy_ansible_task], hosts)
