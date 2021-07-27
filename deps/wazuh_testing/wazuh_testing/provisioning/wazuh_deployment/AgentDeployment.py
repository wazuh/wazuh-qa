
from tempfile import gettempdir

from wazuh_testing.provisioning.wazuh_deployment.WazuhDeployment import WazuhDeployment
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner


class AgentDeployment(WazuhDeployment):

    def __init__(self, installation_files_path, system, inventory_file_path, install_mode='package',
                install_dir='/var/ossec', server_ip=None, hosts='all', preloaded_vars_file=gettempdir()):
        super().__init__(installation_files_path=installation_files_path, system=system,
                         inventory_file_path=inventory_file_path, server_ip=server_ip,
                         install_mode=install_mode, install_dir=install_dir,
                         hosts=hosts, preloaded_vars_file=preloaded_vars_file)

    def install(self):
        super().install('agent')
        self.register_agent()
        self.start_service()

    def start_service(self):
        super().start_service('agent')

    def restart_service(self):
        super().restart_service('agent')

    def stop_service(self):
        super().stop_service('agent')

    def register_agent(self):
        tasks_list = []

        tasks_list.append(AnsibleTask({'name': 'Configuring server ip to autoenrollment agent',
                                       'lineinfile': {'path': f'{self.install_dir}/etc/ossec.conf',
                                                      'regexp': '<address>(.*)</address>',
                                                      'line': f'<address>{self.server_ip}</address>',
                                                      'backrefs': 'yes'},
                                       'when': 'ansible_system != "Windows"'}))

        tasks_list.append(AnsibleTask({'name': 'Configuring server ip to autoenrollment agent',
                                       'lineinfile': {'path': f'{self.install_dir}\\ossec.conf',
                                                      'regexp': '<address>(.*)</address>',
                                                      'line': f'<address>{self.server_ip}</address>',
                                                      'backrefs': 'yes'},
                                       'when': 'ansible_system == "Windows"'}))\

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        self.stop_service()
        AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)
        self.start_service()
