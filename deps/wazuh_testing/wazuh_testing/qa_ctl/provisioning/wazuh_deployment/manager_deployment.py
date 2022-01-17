
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_deployment import WazuhDeployment
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner


class ManagerDeployment(WazuhDeployment):
    """Deploy Wazuh manager with all the elements needed, set from the configuration file

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
        """Child method to install Wazuh in manager

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().install('server')
        self.start_service()

    def start_service(self):
        """Child method to start service in manager

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().start_service('manager')

    def restart_service(self):
        """Child method to start service in manager

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().restart_service('manager')

    def stop_service(self):
        """Child method to start service in manager

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().stop_service('manager')

    def health_check(self):
        """Check if the installation is full complete, and the necessary items are ready

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        super().health_check()

        tasks_list = []
        tasks_list.append(AnsibleTask({
            'name': 'Extract service status',
            'command': f'{self.install_dir_path}/bin/wazuh-control status',
            'when': 'ansible_system != "Win32NT"',
            'register': 'status',
            'failed_when': ['"wazuh-analysisd is running" not in status.stdout or' +
                            '"wazuh-db is running" not in status.stdout or' +
                            '"wazuh-authd is running" not in status.stdout']
        }))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        return AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters,
                                                 output=self.qa_ctl_configuration.ansible_output)
