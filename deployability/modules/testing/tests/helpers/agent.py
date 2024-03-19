import yaml
import requests

from .executor import Executor, WazuhAPI
from .generic import HostInformation
from .constants import WAZUH_CONTROL, CLUSTER_CONTROL, AGENT_CONTROL, CLIENT_KEYS, WAZUH_CONF, WAZUH_ROOT
from typing import List, Optional

class WazuhAgent:

    @staticmethod
    def install_agent(inventory_path, agent_name, wazuh_version, wazuh_revision, live) -> None:

        if live == True:
            s3_url = 'packages'
            release = wazuh_version[0:3]
        else:
            s3_url = 'packages-dev'
            release = 'pre-release'

        os_type = HostInformation.get_os_type(inventory_path)
        commands = []
        if 'linux' in os_type:
            distribution = HostInformation.get_linux_distribution(inventory_path)
            architecture = HostInformation.get_architecture(inventory_path)

            if distribution == 'rpm' and 'x86_64' in architecture:
                commands.extend([
                    f"curl -o wazuh-agent-{wazuh_version}-1.x86_64.rpm https://{s3_url}.wazuh.com/{release}/yum/wazuh-agent-{wazuh_version}-1.x86_64.rpm && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='{agent_name}' rpm -ihv wazuh-agent-{wazuh_version}-1.x86_64.rpm"
                ])
            elif distribution == 'rpm' or distribution == 'opensuse-leap' or distribution == 'amzn' and 'aarch64' in architecture:
                commands.extend([
                    f"curl -o wazuh-agent-{wazuh_version}-1aarch64.rpm https://{s3_url}.wazuh.com/{release}/yum/wazuh-agent-{wazuh_version}-1.aarch64.rpm && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='{agent_name}' rpm -ihv wazuh-agent-{wazuh_version}-1.aarch64.rpm"
                ])
            elif distribution == 'deb' and 'x86_64' in architecture:
                commands.extend([
                    f"wget https://{s3_url}.wazuh.com/{release}/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}-1_amd64.deb && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='{agent_name}' dpkg -i ./wazuh-agent_{wazuh_version}-1_amd64.deb"
                ])
            elif distribution == 'deb' and 'aarch64' in architecture:
                commands.extend([
                    f"wget https://{s3_url}.wazuh.com/{release}/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}-1_arm64.deb && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='{agent_name}' dpkg -i ./wazuh-agent_{wazuh_version}-1arm64.deb"
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
                f"Invoke-WebRequest -Uri https://packages.wazuh.com/{release}/windows/wazuh-agent-{wazuh_version}-1.msi"
                "-OutFile ${env.tmp}\wazuh-agent;"
                "msiexec.exe /i ${env.tmp}\wazuh-agent /q"
                f"WAZUH_MANAGER='MANAGER_IP'"
                f"WAZUH_AGENT_NAME='{agent_name}'"
                f"WAZUH_REGISTRATION_SERVER='MANAGER_IP'",
                "NET START WazuhSvc",
                "NET STATUS WazuhSvc"
                ])
        elif 'macos' in os_type:
            if 'intel' in architecture:
                commands.extend([
                    f'curl -so wazuh-agent.pkg https://{s3_url}.wazuh.com/{release}/macos/wazuh-agent-{wazuh_version}-1.intel64.pkg && echo "WAZUH_MANAGER=\'MANAGER_IP\' && WAZUH_AGENT_NAME=\'{agent_name}\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
                ])
            elif 'apple' in architecture:
                commands.extend([
                    f'curl -so wazuh-agent.pkg https://{s3_url}.wazuh.com/{release}/macos/wazuh-agent-{wazuh_version}-1.arm64.pkg && echo "WAZUH_MANAGER=\'MANAGER_IP\' && WAZUH_AGENT_NAME=\'{agent_name}\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
                ])
            system_commands = [
                    '/Library/Ossec/bin/wazuh-control start',
                    '/Library/Ossec/bin/wazuh-control status'
            ]

            commands.extend(system_commands)
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def install_agents(inventories_paths=[], wazuh_versions=[], wazuh_revisions=[], agent_names=[], live=[]) -> None:
        for index, inventory_path in enumerate(inventories_paths):
            WazuhAgent.install_agent(inventory_path, wazuh_versions[index], wazuh_revisions[index], agent_names[index], live[index])


    @staticmethod
    def register_agent(inventory_path, manager_path):

        with open(manager_path, 'r') as yaml_file:
            manager_path = yaml.safe_load(yaml_file)
        host = manager_path.get('ansible_host')
        
        commands = [
            f"sed -i 's/<address>MANAGER_IP<\/address>/<address>{host}<\/address>/g' {WAZUH_CONF}",
            "systemctl restart wazuh-agent"
            ]

        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_agent(inventory_path, wazuh_version=None, wazuh_revision=None) -> None:
        os_type = HostInformation.get_os_type(inventory_path)
        commands = []
        if 'linux' in os_type:
            distribution = HostInformation.get_linux_distribution(inventory_path)
            os_name = HostInformation.get_os_name_from_inventory(inventory_path)
            if os_name == 'opensuse' or os_name == 'suse':
                    commands.extend([
                        "zypper remove --no-confirm wazuh-agent",
                        "rm -r /var/ossec"
                    ])
            else:
                if distribution == 'deb':
                        commands.extend([
                            "apt-get remove --purge wazuh-agent -y"

                        ])
                elif distribution == 'rpm':
                    commands.extend([
                        "yum remove wazuh-agent -y",
                        f"rm -rf {WAZUH_ROOT}"
                    ])


            system_commands = [
                    "systemctl disable wazuh-agent",
                    "systemctl daemon-reload"
            ]

            commands.extend(system_commands)
        elif 'windows' in os_type:
            commands.extend([
                f"msiexec.exe /x wazuh-agent-{wazuh_version}-1.msi /qn"
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
        print(commands)
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_agents( inventories_paths=[], wazuh_version: Optional[List[str]]=None, wazuh_revision: Optional[List[str]]=None) -> None:
        for index, inventory_path in enumerate(inventories_paths):
            WazuhAgent.uninstall_agent(inventory_path, wazuh_version[index], wazuh_revision[index])



## ----------- api

    def get_agents_information(wazuh_api: WazuhAPI) -> list:
        """
        Get information about agents.

        Returns:
            List: Information about agents.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['affected_items']

    def get_agent_status(wazuh_api: WazuhAPI, agent_name) -> str:
        """
        Function to get the status of an agent given its name.
        
        Args:
        - agents_data (list): List of dictionaries containing agents' data.
        - agent_name (str): Name of the agent whose status is to be obtained.
        
        Returns:
        - str: Status of the agent if found in the data, otherwise returns None.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents", headers=wazuh_api.headers, verify=False)
        for agent in eval(response.text)['data']['affected_items']:
            if agent.get('name') == agent_name:
                return agent.get('status')
        return None


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
