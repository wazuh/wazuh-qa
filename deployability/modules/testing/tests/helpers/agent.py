from executor import Executor
from generic import HostInformation

class WazuhAgent:
    def __init__(self):
        pass

    def install_agent(self, inventory_path):
        hostinformation = HostInformation()
        os_type = hostinformation.get_os_type(inventory_path)
        if 'linux' in os_type:
            distribution = hostinformation.get_linux_distribution(inventory_path)
            architecture = hostinformation.get_architecture(inventory_path)

            if 'rpm' in distribution and 'x86_64' in architecture:
                commands = [
                    "curl -o wazuh-agent-4.7.0-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.x86_64.rpm && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' rpm -ihv wazuh-agent-4.7.0-1.x86_64.rpm"
                ]
            elif 'rpm' in distribution and 'aarch64' in architecture:
                commands = [
                    "curl -o wazuh-agent-4.7.0-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.aarch64.rpm && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' rpm -ihv wazuh-agent-4.7.0-1.aarch64.rpm"
                ]
            elif 'deb' in distribution and 'x86_64' in architecture:
                commands = [
                    "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb"
                ]
            elif 'deb' in distribution and 'aarch64' in architecture:
                commands = [
                    "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_arm64.deb && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' dpkg -i ./wazuh-agent_4.7.0-1_arm64.deb"
                ]
            system_commands = [
                    "systemctl daemon-reload",
                    "systemctl enable wazuh-agent",
                    "systemctl start wazuh-agent",
                    "systemctl status wazuh-agent"
            ]

            commands.append(system_commands)
        elif 'windows' in os_type :
            commands = [
                "Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' WAZUH_REGISTRATION_SERVER='192.168.57.2'",
                "NET START WazuhSvc",
                "NET STATUS WazuhSvc"
                ]
        elif 'macos' in os_type:
            if 'intel' in architecture:
                commands = [
                    'curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.intel64.pkg && echo "WAZUH_MANAGER=\'192.168.57.2\' && WAZUH_AGENT_NAME=\'agente\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
                ]
            elif 'apple' in architecture:
                commands = [
                    'curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.arm64.pkg && echo "WAZUH_MANAGER=\'192.168.57.2\' && WAZUH_AGENT_NAME=\'agente\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
                ]
            system_commands = [
                    '/Library/Ossec/bin/wazuh-control start',
                    '/Library/Ossec/bin/wazuh-control status'
            ]

            commands.append(system_commands)
        Executor.execute_commands(inventory_path, commands)


    def install_agents(self, inventories_paths=[]):
        for inventory_path in inventories_paths:
            self.install_agent(inventory_path)


    def uninstall_agent(self, inventory_path):
        hostinformation = HostInformation()
        os_type = hostinformation.get_os_type(inventory_path)

        if 'linux' in os_type:
            distribution = hostinformation.get_linux_distribution(inventory_path)
            if 'rpm' in distribution:
                commands = [
                    "yum remove wazuh-agent -y",
                    "rm -rf /var/ossec/"
                ]

            elif 'deb' in distribution:
                commands = [
                    "apt-get remove --purge wazuh-agent -y"

                ]
            system_commands = [
                    "systemctl disable wazuh-agent",
                    "systemctl daemon-reload"
            ]

            commands.append(system_commands)
        elif 'windows' in os_type:
            commands = [
                "msiexec.exe /x wazuh-agent-4.7.3-1.msi /qn"
            ]
        elif 'macos' in os_type:
            commands = [
                "/Library/Ossec/bin/wazuh-control stop",
                "/bin/rm -r /Library/Ossec",
                "/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist",
                "/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist",
                "/bin/rm -rf /Library/StartupItems/WAZUH",
                "/usr/bin/dscl . -delete '/Users/wazuh'",
                "/usr/bin/dscl . -delete '/Groups/wazuh'",
                "/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent"
            ]
        Executor.execute_commands(inventory_path, commands)


    def uninstall_agents(self, inventories_paths=[]):
        for inventory_path in inventories_paths:
            self.uninstall_agent(inventory_path)


    def get_agent_status(self, inventory_path):
        """
        Returns the Agent's status

        Args:
            inventory_path: host's inventory path

        Returns:
            str: status
        """
        return Executor.execute_command(inventory_path, 'systemctl status wazuh-agent')


    def agent_stop(self, inventory_path):
        """
        Stops the agent

        Args:
            inventory_path: host's inventory path
        """
        Executor.execute_command(inventory_path, 'systemctl stop wazuh-agent')


    def agent_start(self, inventory_path):
        """
        Starts the agent

        Args:
            inventory_path: host's inventory path
        """
        Executor.execute_command(inventory_path, 'systemctl start wazuh-agent')


    def agent_restart(self, inventory_path):
        """
        Restarts the agent

        Args:
            inventory_path: host's inventory path
        """
        Executor.execute_command(inventory_path, 'systemctl restart wazuh-agent')


    def get_agent_version(self, inventory_path):
        """
        It returns the Agent version

        Args:
            inventory_path: host's inventory path

        Returns:
            str: version
        """
        return Executor.execute_command(inventory_path, '/var/ossec/bin/wazuh-control info -v')


    def get_agent_revision(self, inventory_path):
        """
        It returns the Agent revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: revision number
        """
        return Executor.execute_command(inventory_path, '/var/ossec/bin/wazuh-control info -r')


    def hasAgentClientKeys(self, inventory_path):
        """
        It returns the True of False depending if in the Agent Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        return 'true' in Executor.execute_command(inventory_path, '[ -f /var/ossec/etc/client.keys ] && echo true || echo false')


    def isAgentActive(self, inventory_path):
        """
        It returns the True of False depending if the Agent is Active

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        return Executor.execute_command(inventory_path, 'systemctl is-active wazuh-agent') == 'active'


#---------------------------------------------------


#inv = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
#print(WazuhAgent().uninstall_agent(inv[0]))


