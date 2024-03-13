from .executor import Executor
from .generic import HostInformation
from .constants import WAZUH_CONTROL, CLUSTER_CONTROL, AGENT_CONTROL, CLIENT_KEYS, WAZUH_CONF, WAZUH_ROOT

class WazuhAgent:

    @staticmethod
    def install_agent(inventory_path) -> None:

        os_type = HostInformation.get_os_type(inventory_path)
        commands = []
        if 'linux' in os_type:
            distribution = HostInformation.get_linux_distribution(inventory_path)
            architecture = HostInformation.get_architecture(inventory_path)

            if distribution == 'rpm' or distribution == 'opensuse-leap' or distribution == 'amzn' and 'x86_64' in architecture:
                commands.extend([
                    "curl -o wazuh-agent-4.7.0-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.x86_64.rpm && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' rpm -ihv wazuh-agent-4.7.0-1.x86_64.rpm"
                ])
            elif distribution == 'rpm' or distribution == 'opensuse-leap' or distribution == 'amzn' and 'aarch64' in architecture:
                commands.extend([
                    "curl -o wazuh-agent-4.7.0-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.aarch64.rpm && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' rpm -ihv wazuh-agent-4.7.0-1.aarch64.rpm"
                ])
            elif distribution == 'deb' and 'x86_64' in architecture:
                commands.extend([
                    "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb"
                ])
            elif distribution == 'deb' and 'aarch64' in architecture:
                commands.extend([
                    "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_arm64.deb && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' dpkg -i ./wazuh-agent_4.7.0-1_arm64.deb"
                ])
            system_commands = [
                    "systemctl daemon-reload",
                    "systemctl enable wazuh-agent",
                    "systemctl start wazuh-agent",
                    "systemctl status wazuh-agent"
            ]

            commands.extend(system_commands)
        elif 'windows' in os_type :
            commands.extend([
                "Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' WAZUH_REGISTRATION_SERVER='192.168.57.2'",
                "NET START WazuhSvc",
                "NET STATUS WazuhSvc"
                ])
        elif 'macos' in os_type:
            if 'intel' in architecture:
                commands.extend([
                    'curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.intel64.pkg && echo "WAZUH_MANAGER=\'192.168.57.2\' && WAZUH_AGENT_NAME=\'agente\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
                ])
            elif 'apple' in architecture:
                commands.extend([
                    'curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.arm64.pkg && echo "WAZUH_MANAGER=\'192.168.57.2\' && WAZUH_AGENT_NAME=\'agente\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
                ])
            system_commands = [
                    '/Library/Ossec/bin/wazuh-control start',
                    '/Library/Ossec/bin/wazuh-control status'
            ]

            commands.extend(system_commands)
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def install_agents(inventories_paths=[]) -> None:
        for inventory_path in inventories_paths:
            WazuhAgent.install_agent(inventory_path)


    @staticmethod
    def uninstall_agent(inventory_path) -> None:
        os_type = HostInformation.get_os_type(inventory_path)
        commands = []
        if 'linux' in os_type:
            distribution = HostInformation.get_linux_distribution(inventory_path)
            if distribution == 'rpm' or distribution == 'opensuse-leap' or distribution == 'amzn':
                commands.extend([
                    "yum remove wazuh-agent -y",
                    f"rm -rf {WAZUH_ROOT}"
                ])

            elif distribution == 'deb':
                commands.extend([
                    "apt-get remove --purge wazuh-agent -y"

                ])
            system_commands = [
                    "systemctl disable wazuh-agent",
                    "systemctl daemon-reload"
            ]

            commands.extend(system_commands)
        elif 'windows' in os_type:
            commands.extend([
                "msiexec.exe /x wazuh-agent-4.7.3-1.msi /qn"
            ])
        elif 'macos' in os_type:
            commands.extend([
                "/Library/Ossec/bin/wazuh-control stop",
                "/bin/rm -r /Library/Ossec",
                "/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist",
                "/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist",
                "/bin/rm -rf /Library/StartupItems/WAZUH",
                "/usr/bin/dscl . -delete '/Users/wazuh'",
                "/usr/bin/dscl . -delete '/Groups/wazuh'",
                "/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent"
            ])
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_agents( inventories_paths=[]) -> None:
        for inventory_path in inventories_paths:
            WazuhAgent.uninstall_agent(inventory_path)


    @staticmethod
    def get_agent_status(inventory_path) -> str:
        """
        Returns the Agent's status

        Args:
            inventory_path: host's inventory path

        Returns:
            str: status
        """
        return Executor.execute_command(inventory_path, 'systemctl status wazuh-agent')


    @staticmethod
    def agent_stop(inventory_path) -> None:
        """
        Stops the agent

        Args:
            inventory_path: host's inventory path
        """
        Executor.execute_command(inventory_path, 'systemctl stop wazuh-agent')


    @staticmethod
    def agent_start(inventory_path) -> None:
        """
        Starts the agent

        Args:
            inventory_path: host's inventory path
        """
        Executor.execute_command(inventory_path, 'systemctl start wazuh-agent')


    @staticmethod
    def agent_restart(inventory_path) -> None:
        """
        Restarts the agent

        Args:
            inventory_path: host's inventory path
        """
        Executor.execute_command(inventory_path, 'systemctl restart wazuh-agent')


    @staticmethod
    def get_agent_version(inventory_path) -> str:
        """
        It returns the Agent version

        Args:
            inventory_path: host's inventory path

        Returns:
            str: version
        """
        return Executor.execute_command(inventory_path, f'{WAZUH_CONTROL} info -v')


    @staticmethod
    def get_agent_revision(inventory_path) -> str:
        """
        It returns the Agent revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: revision number
        """
        return Executor.execute_command(inventory_path, f'{WAZUH_CONTROL} info -r')


    @staticmethod
    def hasAgentClientKeys(inventory_path) -> bool:
        """
        It returns the True of False depending if in the Agent Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        return 'true' in Executor.execute_command(inventory_path, f'[ -f {CLIENT_KEYS} ] && echo true || echo false')


    @staticmethod
    def isAgentActive(inventory_path) -> bool:
        """
        It returns the True of False depending if the Agent is Active

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        return Executor.execute_command(inventory_path, 'systemctl is-active wazuh-agent') == 'active'
