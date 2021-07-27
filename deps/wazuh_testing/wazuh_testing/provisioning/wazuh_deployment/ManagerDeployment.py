
from tempfile import gettempdir

from wazuh_testing.provisioning.wazuh_deployment.WazuhDeployment import WazuhDeployment


class ManagerDeployment(WazuhDeployment):

    def __init__(self, installation_files_path, system, inventory_file_path, server_ip=None, install_mode='package',
                install_dir='/var/ossec', hosts='all', preloaded_vars_file=gettempdir()):
        super().__init__(installation_files_path=installation_files_path, system=system, server_ip=server_ip,
                         inventory_file_path=inventory_file_path, install_mode=install_mode, install_dir=install_dir,
                         hosts=hosts, preloaded_vars_file=preloaded_vars_file)

    def install(self):
        super().install('server')
        self.start_service()

    def start_service(self):
        super().start_service('manager')

    def restart_service(self):
        super().restart_service('manager')

    def stop_service(self):
        super().stop_service('manager')
