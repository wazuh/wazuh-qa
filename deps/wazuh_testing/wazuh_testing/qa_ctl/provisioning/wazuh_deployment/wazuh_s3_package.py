import os

from pathlib import Path

from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_package import WazuhPackage
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class WazuhS3Package(WazuhPackage):
    """Install Wazuh from a S3 URL package

    Args:
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        s3_package_url (string): URL of the S3 Wazuh package.
        installation_files_path (string): Path where is located the Wazuh instalation files.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        version (string): The version of Wazuh. Parameter set by default to 'None'.
        system (string): System of the Wazuh installation files. Parameter set by default to 'None'.
        revision (string): Revision of the wazuh package. Parameter set by default to 'None'.
        repository (string): Repository of the wazuh package. Parameter set by default to 'None'.
        architecture (string): Architecture of the Wazuh package. Parameter set by default to 'None'.

    Attributes:
        wazuh_target (string): Type of the Wazuh instance desired (agent or manager).
        s3_package_url (string): URL of the S3 Wazuh package.
        package_name (string): Name of the S3 package.
        installation_files_path (string): Path where is located the Wazuh instalation files.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        version (string): The version of Wazuh. Parameter set by default to 'None'.
        system (string): System of the Wazuh installation files. Parameter set by default to 'None'.
        revision (string): Revision of the wazuh package. Parameter set by default to 'None'.
        repository (string): Repository of the wazuh package. Parameter set by default to 'None'.
        architecture (string): Architecture of the Wazuh package. Parameter set by default to 'None'.
    """

    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, wazuh_target, s3_package_url, installation_files_path, qa_ctl_configuration, version=None,
                 system=None, revision=None, repository=None, architecture=None):
        self.revision = revision
        self.repository = repository
        self.architecture = architecture
        self.s3_package_url = s3_package_url
        self.package_name = Path(self.s3_package_url).name
        super().__init__(wazuh_target=wazuh_target, installation_files_path=installation_files_path, version=version,
                         system=system, qa_ctl_configuration=qa_ctl_configuration)

    def get_package_name(self):
        pass


    def get_s3_package_url(self):
        pass

    def download_installation_files(self, s3_package_url, inventory_file_path, hosts='all'):
        """Download the installation files of Wazuh in the given inventory file path

        Args:
            s3_package_url (string): URL of the S3 Wazuh package.
            inventory_file_path (string): path where the instalation files are going to be stored.
            hosts (string): Parameter set to `all` by default.
        
        Returns:
            str: String with the complete path of the downloaded installation package
        """   
        WazuhS3Package.LOGGER.debug(f"Downloading Wazuh S3 package from <url> in {hosts} hosts")

        download_s3_package = AnsibleTask({'name': 'Download S3 package',
                                           'get_url': {'url': s3_package_url,
                                                       'dest': self.installation_files_path},
                                           'register': 'download_state', 'retries': 6, 'delay': 10,
                                           'until': 'download_state is success'})
        WazuhS3Package.LOGGER.debug(f"Wazuh S3 package was successfully downloaded in {hosts} hosts")

        super().download_installation_files(inventory_file_path, [download_s3_package], hosts)

        return os.path.join(self.installation_files_path, self.package_name)

