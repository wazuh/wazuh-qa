from abc import ABC, abstractmethod

from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_installation import WazuhInstallation


class WazuhPackage(WazuhInstallation, ABC):
    """Install Wazuh from the given sources. In this case, the installation
        will be done from a package file.

    Args:
        version (string): The version of Wazuh.
        system (string): System of the Wazuh installation files.
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        installation_files_path (string): Path where is located the Wazuh instalation files.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.

    Attributes:
        version (string): The version of Wazuh.
        system (string): System of the Wazuh installation files.
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        installation_files_path (string): Path where is located the Wazuh instalation files.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
    """
    def __init__(self, version, system, wazuh_target, installation_files_path, qa_ctl_configuration):
        self.version = version
        self.system = system
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path,
                         qa_ctl_configuration=qa_ctl_configuration)

    @abstractmethod
    def download_installation_files(self, inventory_file_path, ansible_tasks, hosts='all'):
        """Download the installation files of Wazuh.

        Args:
            inventory_file_path (string): path where the instalation files are going to be stored
            ansible_tasks (ansible object): ansible instance with already provided tasks to run
            hosts (string): Parameter set to `all` by default
        """
        super().download_installation_files(inventory_file_path, ansible_tasks, hosts)
