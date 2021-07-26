from wazuh_testing.provisioning.wazuh_deployment.WazuhInstallation import WazuhInstallation
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask


class WazuhSources(WazuhInstallation):

    def __init__(self, wazuh_target, installation_files_path, wazuh_branch='master',
                 wazuh_repository_url='https://github.com/wazuh/wazuh.git'):
        self.wazuh_branch = wazuh_branch
        self.wazuh_repository_url = wazuh_repository_url
        super().__init__(wazuh_target=wazuh_target, installation_files_path=f"{installation_files_path}/wazuh")

    def download_installation_files(self, inventory_file_path, hosts='all'):
        download_wazuh_sources_task = AnsibleTask({'name': 'Clone wazuh repository',
                                                   'git': {'repo': self.wazuh_repository_url,
                                                           'dest': self.installation_files_path,
                                                           'version': self.wazuh_branch}})
        super().download_installation_files(inventory_file_path, [download_wazuh_sources_task], hosts)
