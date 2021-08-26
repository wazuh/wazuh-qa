import os

from pathlib import Path

from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.WazuhPackage import WazuhPackage
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class LocalPackage(WazuhPackage):
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, wazuh_target, installation_files_path, local_package_path, qa_ctl_configuration, version=None,
                 system=None):
        self.local_package_path = local_package_path
        self.package_name = Path(self.local_package_path).name
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path, version=version,
                         system=system, qa_ctl_configuration=qa_ctl_configuration)

    def download_installation_files(self, inventory_file_path, hosts='all'):
        copy_ansible_task = AnsibleTask({'name': f"Copy {self.local_package_path} package to \
                                                   {self.installation_files_path}",
                                                 'copy': {'src': self.local_package_path,
                                                          'dest': self.installation_files_path}})
        LocalPackage.LOGGER.debug(f"Copying local package {self.local_package_path} to {self.installation_files_path}"
                                  f" in {hosts} hosts")
        super().download_installation_files(inventory_file_path, [copy_ansible_task], hosts)

        return os.path.join(self.installation_files_path, self.package_name)
