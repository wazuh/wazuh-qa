import os
from pathlib import Path

from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_package import WazuhPackage
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class WazuhLocalPackage(WazuhPackage):
    """Install Wazuh from a local existent package

    Args:
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        installation_files_path (string): Path where is located the Wazuh instalation files.
        local_package_path (string): Path where the local package is located.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        version (string): The version of Wazuh. Parameter set by default to 'None'.
        system (string): System of the Wazuh installation files. Parameter set by default to 'None'.

    Attributes:
        local_package_path (string): Path where the local package is located.
        package_name (string): name of the Wazuh package.
        installation_files_path (string): Path where the Wazuh installation files are located.
        local_package_path (string): Path where the local package is located.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, wazuh_target, installation_files_path, local_package_path, qa_ctl_configuration, version=None,
                 system=None):
        self.local_package_path = local_package_path
        self.package_name = Path(self.local_package_path).name
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path, version=version,
                         system=system, qa_ctl_configuration=qa_ctl_configuration)

    def download_installation_files(self, inventory_file_path, hosts='all'):
        """Download the installation files of Wazuh in the given inventory file path

        Args:
            inventory_file_path (string): path where the instalation files are going to be stored.
            hosts (string): Parameter set to `all` by default.

        Returns:
            str: String with the complete path of the installation package
        """
        WazuhLocalPackage.LOGGER.debug(f"Copying local package {self.local_package_path} to "
                                       f"{self.installation_files_path} in {hosts} hosts")

        copy_ansible_task = AnsibleTask({
            'name': f"Copy {self.local_package_path} package to {self.installation_files_path}",
            'copy': {'src': self.local_package_path, 'dest': self.installation_files_path}
        })

        WazuhLocalPackage.LOGGER.debug(f"{self.local_package_path} has been successfully copied in {hosts} hosts")

        super().download_installation_files(inventory_file_path, [copy_ansible_task], hosts)

        return os.path.join(self.installation_files_path, self.package_name)
