
from wazuh_testing.provisioning.wazuh_install.WazuhDeployment import WazuhDeployment


class ManagerDeployment(WazuhDeployment):

    def install(self):
        super().install('server')

    def start_service(self):
        super().start_service('manager')

    def restart_service(self):
        super().restart_service('manager')

    def stop_service(self):
        super().stop_service('manager')
