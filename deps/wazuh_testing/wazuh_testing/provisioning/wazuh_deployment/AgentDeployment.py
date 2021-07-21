
from tempfile import gettempdir

from wazuh_testing.provisioning.wazuh_deployment.WazuhDeployment import WazuhDeployment
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner


class AgentDeployment(WazuhDeployment):
    """Deploy Wazuh agent with all the elements needed, set from the configuration file

    Args:
        installation_files (string): Path where is located the Wazuh instalation files.
        configuration (WazuhConfiguration): Configuration object to be set.
        inventory_file_path (string): Path where is located the ansible inventory file.
        install_mode (string): 'package' or 'sources' installation mode.
        install_dir_path (string): Path where the Wazuh installation will be stored.
        hosts (string): Group of hosts to be deployed.
        server_ip (string): Manager IP to connect.

    Attributes:
        installation_files (string): Path where is located the Wazuh instalation files.
        configuration (WazuhConfiguration): Configuration object to be set.
        inventory_file_path (string): Path where is located the ansible inventory file.
        install_mode (string): 'package' or 'sources' installation mode.
        install_dir_path (string): Path where the Wazuh installation will be stored.
        hosts (string): Group of hosts to be deployed.
        server_ip (string): Manager IP to connect.
    """

    def install(self):
        """Child method to install Wazuh in agent

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().install('agent')
        self.register_agent()

    def start_service(self):
        """Child method to start service in agent

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().start_service('agent')

    def restart_service(self):
        """Child method to restart service in agent

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().restart_service('agent')

    def stop_service(self):
        """Child method to stop service in agent

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().stop_service('agent')

    def register_agent(self):
        """Set the manager ip in the ossec.conf, and restart Wazuh agent to let autoenrollment register it.

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        tasks_list = []

        tasks_list.append(AnsibleTask({'name': 'Configuring server ip to autoenrollment agent',
                                       'lineinfile': {'path': f'{self.install_dir_path}/etc/ossec.conf',
                                                      'regexp': '<address>(.*)</address>',
                                                      'line': f'<address>{self.server_ip}</address>',
                                                      'backrefs': 'yes'},
                                       'when': 'ansible_system != "Windows"'}))

        tasks_list.append(AnsibleTask({'name': 'Configuring server ip to autoenrollment agent',
                                       'lineinfile': {'path': f'{self.install_dir_path}\\ossec.conf',
                                                      'regexp': '<address>(.*)</address>',
                                                      'line': f'<address>{self.server_ip}</address>',
                                                      'backrefs': 'yes'},
                                       'when': 'ansible_system == "Windows"'}))\

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        self.stop_service()

        output = AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)

        self.start_service()

        return output

    def health_check(self):
        """Check if the installation is full complete, and the necessary items are ready

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().health_check()

        tasks_list = []
        tasks_list.append(AnsibleTask({'name': 'Extract service status',
                                       'command': f'{self.install_dir}/bin/wazuh-control status',
                                       'when': 'ansible_system != "Windows"',
                                       'register': 'status'}))

        tasks_list.append(AnsibleTask({'name': 'Check services',
                                       'failed_when': ['"wazuh-agentd" not in status.stdout',
                                                       '"wazuh-execd" not in status.stdout']}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        return AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)
