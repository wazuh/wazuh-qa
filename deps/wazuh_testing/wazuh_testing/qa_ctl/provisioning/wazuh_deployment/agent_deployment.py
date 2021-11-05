
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_deployment import WazuhDeployment
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner


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
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        ansible_admin_user (str): User to launch the ansible task with admin privileges (ansible_become_user)

    Attributes:
        installation_files (string): Path where is located the Wazuh instalation files.
        configuration (WazuhConfiguration): Configuration object to be set.
        inventory_file_path (string): Path where is located the ansible inventory file.
        install_mode (string): 'package' or 'sources' installation mode.
        install_dir_path (string): Path where the Wazuh installation will be stored.
        hosts (string): Group of hosts to be deployed.
        server_ip (string): Manager IP to connect.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        ansible_admin_user (str): User to launch the ansible task with admin privileges (ansible_become_user)
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

        tasks_list.append(AnsibleTask({
            'name': 'Configuring server ip to autoenrollment Unix agent',
            'lineinfile': {'path': f'{self.install_dir_path}/etc/ossec.conf',
                           'regexp': '<address>(.*)</address>',
                           'line': f'<address>{self.server_ip}</address>',
                           'backrefs': 'yes'},
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }))

        tasks_list.append(AnsibleTask({
            'name': 'Configuring server ip to autoenrollment Windows agent',
            'win_lineinfile': {'path': f'{self.install_dir_path}\\ossec.conf',
                               'regexp': '<address>(.*)</address>',
                               'line': f'<address>{self.server_ip}</address>',
                               'backrefs': 'yes'},
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': False}

        self.stop_service()

        output = AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters,
                                                   output=self.qa_ctl_configuration.ansible_output)

        self.start_service()

        return output

    def health_check(self):
        """Check if the installation is full complete, and the necessary items are ready

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().health_check()

        tasks_list = []
        tasks_list.append(AnsibleTask({
            'name': 'Extract service status',
            'command': f"{self.install_dir_path}/bin/wazuh-control status",
            'when': 'ansible_system != "Win32NT"',
            'register': 'status',
            'become': True,
            'failed_when': ['"wazuh-agentd" not in status.stdout',
                            '"wazuh-execd" not in status.stdout']
        }))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': False}

        return AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters,
                                                 output=self.qa_ctl_configuration.ansible_output)
