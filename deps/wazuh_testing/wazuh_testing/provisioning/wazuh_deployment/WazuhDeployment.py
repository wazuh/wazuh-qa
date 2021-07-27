
from abc import ABC, abstractmethod
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner
import sys


class WazuhDeployment(ABC):

    def __init__(self, installation_files, system, configuration=None, inventory='/tmp/inventory.yaml',
                 install_mode='sources', install_dir='/var/ossec', ip_server=None, hosts='all',
                 services=[]):
        self.installation_files = installation_files
        self.configuration = configuration
        self.inventory = inventory
        self.install_mode = install_mode
        self.install_dir = install_dir
        self.ip_server = ip_server
        self.hosts = hosts
        self.services = services

    @abstractmethod
    def install(self, install_type):
        tasks_list = []
        if self.install_mode == 'sources':
            tasks_list.append(AnsibleTask({
                    'name': 'Install dependencies to build Wazuh packages',
                    'package': {'name': ['make', 'gcc', 'automake', 'autoconf', 'libtool',
                                         'tar', 'libc6-dev', 'curl', 'policycoreutils'],
                                'state': 'present'}}))

            tasks_list.append(AnsibleTask({
                'name': 'Clean remaining files from others builds',
                'command': 'make -C src {{ item }}',
                'args': {'chdir': f'{self.installation_files}'},
                'with_items': ['clean', 'clean-deps'],
                'when': 'ansible_system == "Linux"'}))

            tasks_list.append(AnsibleTask({
                'name': 'Render the "preloaded-vars.conf" file',
                'template': {'src': 'wazuh_testing/provisioning/wazuh_install/templates/preloaded_vars.conf.j2',
                             'dest': f'{self.installation_files}/etc/preloaded-vars.conf',
                             'owner': 'root',
                             'group': 'root',
                             'mode': '0644'},
                'vars': {'install_type': install_type,
                         'install_dir': f'{self.install_dir}',
                         'ip_server': f'{self.ip_server}',
                         'ca_store': f'{self.installation_files}/wpk_root.pem',
                         'make_cert': 'y' if install_type == 'server' else 'n'},
                'when': 'ansible_system == "Linux"'}))

            tasks_list.append(AnsibleTask({
                'name': 'Executing "install.sh" script to build and install Wazuh',
                'shell': './install.sh > /tmp/wazuh_install_log.txt',
                'args': {'chdir': f'{self.installation_files}'},
                'when': 'ansible_system == "Linux"'}))

        elif self.install_mode == 'package':
            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from .deb packages',
                                           'apt': {'deb': f'{self.installation_files}'},
                                           'when': 'ansible_os_family|lower == "debian"'}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from .rpm packages | yum',
                                           'yum': {'name': f'{self.installation_files}'},
                                           'when': ['ansible_os_family|lower == "redhat"',
                                                    'not (ansible_distribution|lower == "centos" and ' +
                                                    'ansible_distribution_major_version >= "8")',
                                                    'not (ansible_distribution|lower == "redhat" and ' +
                                                    'ansible_distribution_major_version >= "8")']}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from .rpm packages | dnf',
                                           'dnf': {'name': f'{self.installation_files}'},
                                           'when': ['ansible_os_family|lower == "redhat"',
                                                    '(ansible_distribution|lower == "centos" and ' +
                                                    'ansible_distribution_major_version >= "8") or' +
                                                    '(ansible_distribution|lower == "redhat" and ' +
                                                    'ansible_distribution_major_version >= "8")']}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from Windows packages',
                                           'win_package': {'path': f'{self.installation_files}'},
                                           'when': 'ansible_system == "Windows"'}))

            tasks_list.append(AnsibleTask({'name': 'Install macOS wazuh package',
                                           'shell': 'installer -pkg wazuh-* -target /',
                                           'args': {'chdir': f'{self.installation_files}'},
                                           'when': 'ansible_system == "Darwin"'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        AnsibleRunner.run_ephemeral_tasks(self.inventory, playbook_parameters)

    def __control_service(self, command, install_type):
        tasks_list = []
        service_name = install_type if install_type == 'agent' else 'manager'
        service_command = f'{command}ed' if command != 'stop' else 'stopped'

        tasks_list.append(AnsibleTask({'name': f'Wazuh manager {command} service',
                                       'become': True,
                                       'systemd': {'name': f'wazuh-{service_name}',
                                                   'state': f'{service_command}'},
                                       'register': 'output_command',
                                       'ignore_errors': 'true',
                                       'when': 'ansible_system == "Linux"'}))

        tasks_list.append(AnsibleTask({'name': f'Wazuh agent {command} service',
                                       'become': True,
                                       'command': f'{self.install_dir}/bin/wazuh-control {command}',
                                       'when': 'ansible_system == "darwin" or ansible_system == "SunOS" or ' +
                                               'output_command.failed == true'}))

        tasks_list.append(AnsibleTask({'name': f'Wazuh agent {command} service',
                                       'win_shell': 'Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue |' +
                                                    f' {command.capitalize()}-Service -ErrorAction SilentlyContinue',
                                       'args': {'executable': 'powershell.exe'},
                                       'when': 'ansible_system == "Windows"'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        AnsibleRunner.run_ephemeral_tasks(self.inventory, playbook_parameters)

    @abstractmethod
    def start_service(self, install_type):
        self.__control_service('start', install_type)

    @abstractmethod
    def restart_service(self, install_type):
        self.__control_service('restart', install_type)

    @abstractmethod
    def stop_service(self, install_type):
        self.__control_service('stop', install_type)
