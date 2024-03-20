import requests
from .executor import Executor, WazuhAPI
from .generic import HostInformation
from .constants import WAZUH_ROOT


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

## ----------- api

    def get_agents_information(wazuh_api: WazuhAPI) -> list:
        """
        Get information about agents.

        Returns:
            List: Information about agents.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['affected_items']


    def get_agent_ip_status_and_name_by_id(wazuh_api: WazuhAPI, identifier):
        """
        Get IP status and name by ID.

        Args:
            identifier (str): Agent ID.

        Returns:
            List: IP, name, and status of the agent.
        """
        agents_information = wazuh_api.get_agents_information()
        for element in agents_information:
            if element['id'] == identifier:
                return [element['ip'], element['name'], element['status']]
        return [None, None, None]


    def add_agent_to_manager(wazuh_api: WazuhAPI, name, ip) -> str:
        """
        Add an agent to the manager.

        Args:
            name (str): Name of the agent.
            ip (str): IP address of the agent.

        Returns:
            str: Response text.
        """
        response = requests.post(f"{wazuh_api.api_url}/agents", json={"name": name ,"ip": ip}, headers=wazuh_api.headers, verify=False)
        return response.text


    def restart_agents(wazuh_api: WazuhAPI) -> str:
        """
        Restart agents.

        Returns:
            str: Response text.
        """
        response = requests.put(f"{wazuh_api.api_url}/agents/restart", headers=wazuh_api.headers, verify=False)
        return response.text


    def agent_status_report(wazuh_api: WazuhAPI) -> dict:
        """
        Get agent status report.

        Returns:
            Dict: Agent status report.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents/summary/status", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']


