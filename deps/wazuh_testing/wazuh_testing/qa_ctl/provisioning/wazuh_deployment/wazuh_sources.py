from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_installation import WazuhInstallation
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask


class WazuhSources(WazuhInstallation):

    def __init__(self, wazuh_target, installation_files_path, wazuh_branch='master',
                 wazuh_repository_url='https://github.com/wazuh/wazuh.git'):
        self.wazuh_branch = wazuh_branch
        self.wazuh_repository_url = wazuh_repository_url
        super().__init__(wazuh_target=wazuh_target, installation_files_path=f"{installation_files_path}/" +
                                                                            f"wazuh-{self.wazuh_branch}")

    def download_installation_files(self, inventory_file_path, hosts='all'):
        download_wazuh_sources_task = AnsibleTask({'name': f"Download Wazuh branch in {self.installation_files_path}",
                                                   'shell': f"cd {self.installation_files_path} && " +
                                                            'curl -Ls https://github.com/wazuh/wazuh/archive/' +
                                                            f"{self.wazuh_branch}.tar.gz | tar zx && mv wazuh-*/* ."})
        super().download_installation_files(inventory_file_path, [download_wazuh_sources_task], hosts)

        return self.installation_files_path
