from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_installation import WazuhInstallation
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class WazuhSources(WazuhInstallation):
    """Install Wazuh from the given sources. In this case, the installation
        will be done from the source files of a repository.

    Args:
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        installation_files_path (string): Path where is located the Wazuh instalation files.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        wazuh_branch (string): String containing the branch from where the files are going to be downloaded.
        This field is set to 'master' by default.
        wazuh_repository_url (string): URL from the repo where the wazuh sources files are located.
        This parameter is set to 'https://github.com/wazuh/wazuh.git' by default.

    Attributes:
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        installation_files_path (string): Path where is located the Wazuh instalation files.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        wazuh_branch (string): String containing the branch from where the files are going to be downloaded.
        This field is set to 'master' by default.
        wazuh_repository_url (string): URL from the repo where the wazuh sources files are located.
        This parameter is set to 'https://github.com/wazuh/wazuh.git' by default.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, wazuh_target, installation_files_path, qa_ctl_configuration, wazuh_branch='master',
                 wazuh_repository_url='https://github.com/wazuh/wazuh.git'):
        self.wazuh_branch = wazuh_branch
        self.wazuh_repository_url = wazuh_repository_url
        super().__init__(wazuh_target=wazuh_target, qa_ctl_configuration=qa_ctl_configuration,
                         installation_files_path=f"{installation_files_path}/wazuh-{self.wazuh_branch}")

    def download_installation_files(self, inventory_file_path, hosts='all'):
        """Download the source files of Wazuh using an AnsibleTask instance.

        Args:
            inventory_file_path (string): path where the instalation files are going to be stored
            hosts (string): Parameter set to `all` by default

        Returns:
            str: String with the path where the installation files are located
        """
        WazuhSources.LOGGER.debug(f"Downloading Wazuh sources from {self.wazuh_branch} branch in {hosts} hosts")

        download_wazuh_sources_task = AnsibleTask({
            'name': f"Download Wazuh branch in {self.installation_files_path}",
            'shell': f"cd {self.installation_files_path} && curl -Ls https://github.com/wazuh/wazuh/archive/"
                     f"{self.wazuh_branch}.tar.gz | tar zx && mv wazuh-*/* ."
        })
        WazuhSources.LOGGER.debug(f"Wazuh sources from {self.wazuh_branch} branch were successfully downloaded in "
                                  f"{hosts} hosts")
        super().download_installation_files(inventory_file_path, [download_wazuh_sources_task], hosts)

        return self.installation_files_path
