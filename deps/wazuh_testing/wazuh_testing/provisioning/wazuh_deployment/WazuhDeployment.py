
from abc import ABC, abstractmethod
from tempfile import gettempdir

from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner


class WazuhDeployment(ABC):

    def __init__(self, installation_files_path, system, inventory_file_path, server_ip=None, install_mode='package',
                 install_dir='/var/ossec', hosts='all', preloaded_vars_file=gettempdir()):
        self.installation_files_path = installation_files_path
        self.system = system
        self.inventory_file_path = inventory_file_path
        self.install_mode = install_mode
        self.install_dir = install_dir
        self.hosts = hosts
        self.preloaded_vars_file = preloaded_vars_file
        self.server_ip = server_ip

    @abstractmethod
    def install(self, install_type):
        tasks_list = []
        if self.install_mode == 'sources':
            tasks_list.append(AnsibleTask({
                'name': 'Render the "preloaded-vars.conf" file',
                'template': {'src': f"{self.preloaded_vars_file}/preloaded_vars.conf.j2",
                                'dest': f'{self.installation_files_path}/etc/preloaded-vars.conf',
                                'owner': 'root',
                                'group': 'root',
                                'mode': '0644'},
                'vars': {'install_type': install_type,
                            'install_dir': f'{self.install_dir}',
                            'ip_server': f'{self.server_ip}',
                            'ca_store': f'{self.installation_files_path}/wpk_root.pem',
                            'make_cert': 'y' if install_type == 'server' else 'n'},
                            'when': 'ansible_system == "Linux"'}))

            tasks_list.append(AnsibleTask({
                'name': 'Executing "install.sh" script to build and install the Wazuh Agent',
                'shell': './install.sh > /tmp/wazuh_install_log.txt',
                'args': {'chdir': f'{self.installation_files_path}'},
                'when': 'ansible_system == "Linux"'}))

        elif self.install_mode == 'package':
            tasks_list.append(AnsibleTask({'name': 'Install Wazuh from DEB packages',
                                           'apt': {'deb': f'{self.installation_files_path}'},
                                           'when': 'ansible_os_family|lower == "debian"'}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh from RPM packages | yum',
                                           'yum': {'name': f'{self.installation_files_path}'},
                                           'when': ['ansible_os_family|lower == "redhat"',
                                                    'not (ansible_distribution|lower == "centos" and ' +
                                                    'ansible_distribution_major_version >= "8")',
                                                    'not (ansible_distribution|lower == "redhat" and ' +
                                                    'ansible_distribution_major_version >= "8")']}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from Windows packages',
                                           'win_package': {'path': f'{self.installation_files_path}'},
                                           'when': 'ansible_system == "Windows"'}))

            tasks_list.append(AnsibleTask({'name': 'Install macOS wazuh package',
                                           'shell': 'installer -pkg wazuh-* -target /',
                                           'args': {'chdir': f'{self.installation_files_path}'},
                                           'when': 'ansible_system == "Darwin"'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)

    def __control_service(self, command, install_type):
        tasks_list = []
        service_name = install_type if install_type == 'agent' else 'manager'
        service_command = f'{command}ed' if command != 'stop' else 'stopped'

        tasks_list.append(AnsibleTask({'name': f'Wazuh manager {command} service from systemd',
                                       'become': True,
                                       'systemd': {'name': f'wazuh-{service_name}',
                                                   'state': f'{service_command}'},
                                       'register': 'output_command',
                                       'ignore_errors': 'true',
                                       'when': 'ansible_system == "Linux"'}))

        tasks_list.append(AnsibleTask({'name': f'Wazuh agent {command} service from wazuh-control',
                                       'become': True,
                                       'command': f'{self.install_dir}/bin/wazuh-control {command}',
                                       'when': 'ansible_system == "Darwin" or ansible_system == "SunOS" or ' +
                                               'output_command.failed == true'}))

        tasks_list.append(AnsibleTask({'name': f'Wazuh agent {command} service from Windows',
                                       'win_shell': 'Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue |' +
                                                    f' {command.capitalize()}-Service -ErrorAction SilentlyContinue',
                                       'args': {'executable': 'powershell.exe'},
                                       'when': 'ansible_system == "Windows"'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)

    @abstractmethod
    def start_service(self, install_type):
        self.__control_service('start', install_type)

    @abstractmethod
    def restart_service(self, install_type):
        self.__control_service('restart', install_type)

    @abstractmethod
    def stop_service(self, install_type):
        self.__control_service('stop', install_type)
