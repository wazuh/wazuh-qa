
from wazuh_testing.provisioning.wazuh_install.WazuhDeployment import WazuhDeployment
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner


class AgentDeployment(WazuhDeployment):

    def install(self):
        super().install('agent')

    def start_service(self):
        super().start_service('agent')

    def restart_service(self):
        super().restart_service('agent')

    def stop_service(self):
        super().stop_service('agent')

    def register_agent(self):
        tasks_list = []

        tasks_list.append(AnsibleTask({'name': 'Configuring server ip to autoenrollment agent',
                                       'lineinfile': {'path': f'{self.install_dir}' +
                                                              ('\\' if self.system == 'windows' else '/etc/') +
                                                              'ossec.conf',
                                                      'regexp': '<address>(.*)</address>',
                                                      'line': f'<address>{self.ip_server}</address>',
                                                      'backrefs': 'yes'}}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'become': True}

        self.stop_service()
        AnsibleRunner.run_ephemeral_tasks(self.inventory, playbook_parameters)
        self.start_service()
