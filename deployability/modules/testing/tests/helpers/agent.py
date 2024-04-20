# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import requests
import yaml

from typing import List, Optional
from .constants import WAZUH_CONF, WAZUH_ROOT, WAZUH_WINDOWS_CONF
from .executor import Executor, WazuhAPI
from .generic import HostInformation, CheckFiles
from modules.testing.utils import logger

class WazuhAgent:

    @staticmethod
    def install_agent(inventory_path, agent_name, wazuh_version, wazuh_revision, live) -> None:

        if live == True:
            s3_url = 'packages'
            release = wazuh_version[:1] + ".x"
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
            elif distribution == 'rpm' and 'aarch64' in architecture:
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
                "-OutFile $env:TEMP\wazuh-agent.msi;"
                "msiexec.exe /i $env:TEMP\wazuh-agent.msi /q"
                f"WAZUH_MANAGER='MANAGER_IP'"
                f"WAZUH_AGENT_NAME='{agent_name}'"
                f"WAZUH_REGISTRATION_SERVER='MANAGER_IP'"
            ])
            commands.extend(["NET START WazuhSvc"])
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
        logger.info(f'Installing Agent in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
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

        internal_ip = HostInformation.get_internal_ip_from_aws_dns(host) if 'amazonaws' in host else host

        os_type = HostInformation.get_os_type(inventory_path)

        if 'linux' in os_type:
            commands = [
                f"sed -i 's/<address>MANAGER_IP<\/address>/<address>{internal_ip}<\/address>/g' {WAZUH_CONF}",
                "systemctl restart wazuh-agent"
            ]

            Executor.execute_commands(inventory_path, commands)

            assert internal_ip in Executor.execute_commands(inventory_path, f'cat {WAZUH_CONF}'), logger.error(f'Error configuring the Manager
            IP ({internal_ip})in: {HostInformation.get_os_name_and_version_from_inventory(inventory_path)} agent')
        elif 'windows' in os_type :
            commands = [
                f'(Get-Content -Path "{WAZUH_WINDOWS_CONF}" -Raw) -replace "<address>MANAGER_IP</address>", "<address>{internal_ip}</address>" | Set-Content -Path "{WAZUH_WINDOWS_CONF}"'
            ]
            commands.extend(["NET STOP WazuhSvc"])
            commands.extend(["NET START WazuhSvc"])

            Executor.execute_commands(inventory_path, commands)

            assert internal_ip in Executor.execute_windows_command(inventory_path, f'Get-Content "{WAZUH_WINDOWS_CONF}"'), logger.error(f'Error configuring the Manager
            IP ({internal_ip})in: {HostInformation.get_os_name_and_version_from_inventory(inventory_path)} agent')


    @staticmethod
    def set_protocol_agent_connection(inventory_path, protocol):
        os_type = HostInformation.get_os_type(inventory_path)

        if 'linux' in os_type:
            commands = [
                f"sed -i 's/<protocol>[^<]*<\/protocol>/<protocol>{protocol}<\/protocol>/g' {WAZUH_CONF}",
                "systemctl restart wazuh-agent"
            ]

            Executor.execute_commands(inventory_path, commands)
            assert protocol in Executor.execute_command(inventory_path, f'cat {WAZUH_CONF}'), logger.error(f'Error configuring the protocol ({protocol}) in: {HostInformation.get_os_name_and_version_from_inventory(inventory_path)} agent')
        elif 'windows' in os_type :
            commands = [
                f"(Get-Content -Path '{WAZUH_WINDOWS_CONF}') -replace '<protocol>[^<]*<\/protocol>', '<protocol>{protocol}</protocol>' | Set-Content -Path '{WAZUH_WINDOWS_CONF}'"
            ]

            Executor.execute_commands(inventory_path, commands)
            assert protocol in Executor.execute_command(inventory_path, f'Get-Content -Path "{WAZUH_WINDOWS_CONF}"'), logger.error(f'Error configuring the protocol ({protocol}) in: {HostInformation.get_os_name_and_version_from_inventory(inventory_path)} agent')


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
                f"msiexec.exe /x $env:TEMP\wazuh-agent.msi /qn"
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

        logger.info(f'Uninstalling Agent in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_agents( inventories_paths=[], wazuh_version: Optional[List[str]]=None, wazuh_revision: Optional[List[str]]=None) -> None:
        for index, inventory_path in enumerate(inventories_paths):
            WazuhAgent.uninstall_agent(inventory_path, wazuh_version[index], wazuh_revision[index])


    @staticmethod
    def _install_agent_callback(wazuh_params, agent_name, agent_params):
        WazuhAgent.install_agent(agent_params, agent_name, wazuh_params['wazuh_version'], wazuh_params['wazuh_revision'], wazuh_params['live'])


    @staticmethod
    def _uninstall_agent_callback(wazuh_params, agent_params):
        WazuhAgent.uninstall_agent(agent_params, wazuh_params['wazuh_version'], wazuh_params['wazuh_revision'])


    @staticmethod
    def perform_action_and_scan(agent_params, action_callback) -> dict:
        """
        Takes scans using filters, the callback action and compares the result

        Args:
            agent_params (str): agent parameters
            callbak (cb): callback (action)

        Returns:
            result (dict): comparison brief

        """
        result = CheckFiles.perform_action_and_scan(agent_params, action_callback)
        os_name = HostInformation.get_os_name_from_inventory(agent_params)
        logger.info(f'Applying filters in checkfiles in {HostInformation.get_os_name_and_version_from_inventory(agent_params)}')

        if 'debian' in os_name:
            filter_data = {
                '/boot': {'added': [], 'removed': [], 'modified': ['grubenv']},
                '/usr/bin': {
                    'added': [
                        'unattended-upgrade', 'gapplication', 'add-apt-repository', 'gpg-wks-server', 'pkexec', 'gpgsplit',
                        'watchgnupg', 'pinentry-curses', 'gpg-zip', 'gsettings', 'gpg-agent', 'gresource', 'gdbus',
                        'gpg-connect-agent', 'gpgconf', 'gpgparsemail', 'lspgpot', 'pkaction', 'pkttyagent', 'pkmon',
                        'dirmngr', 'kbxutil', 'migrate-pubring-from-classic-gpg', 'gpgcompose', 'pkcheck', 'gpgsm', 'gio',
                        'pkcon', 'gpgtar', 'dirmngr-client', 'gpg', 'filebeat', 'gawk', 'curl', 'update-mime-database',
                        'dh_installxmlcatalogs', 'appstreamcli', 'lspgpot', 'symcryptrun'
                    ],
                    'removed': [],
                    'modified': []
                },
                '/root': {'added': ['trustdb.gpg', 'lesshst'], 'removed': [], 'modified': []},
                '/usr/sbin': {
                    'added': [
                        'update-catalog', 'applygnupgdefaults', 'addgnupghome', 'install-sgmlcatalog', 'update-xmlcatalog'
                    ],
                    'removed': [],
                    'modified': []
                }
            }
        else:
            filter_data = {
                '/boot': {
                    'added': ['grub2', 'loader', 'vmlinuz', 'System.map', 'config-', 'initramfs'],
                    'removed': [],
                    'modified': ['grubenv']
                },
                '/usr/bin': {'added': ['filebeat'], 'removed': [], 'modified': []},
                '/root': {'added': ['trustdb.gpg', 'lesshst'], 'removed': [], 'modified': []},
                '/usr/sbin': {'added': [], 'removed': [], 'modified': []}
            }

        # Use of filters
        for directory, changes in result.items():
            if directory in filter_data:
                for change, files in changes.items():
                    if change in filter_data[directory]:
                        result[directory][change] = [file for file in files if file.split('/')[-1] not in filter_data[directory][change]]

        return result

    @staticmethod
    def perform_install_and_scan_for_agent(agent_params, agent_name, wazuh_params) -> None:
        """
        Coordinates the action of install the agent and compares the checkfiles

        Args:
            agent_params (str): agent parameters
            wazuh_params (str): wazuh parameters

        """
        action_callback = lambda: WazuhAgent._install_agent_callback(wazuh_params, agent_name, agent_params)
        result = WazuhAgent.perform_action_and_scan(agent_params, action_callback)
        logger.info(f'Pre and post install checkfile comparison in {HostInformation.get_os_name_and_version_from_inventory(agent_params)}: {result}')
        WazuhAgent.assert_results(result)


    @staticmethod
    def perform_uninstall_and_scan_for_agent(agent_params, wazuh_params) -> None:
        """
        Coordinates the action of uninstall the agent and compares the checkfiles

        Args:
            agent_params (str): agent parameters
            wazuh_params (str): wazuh parameters

        """
        action_callback = lambda: WazuhAgent._uninstall_agent_callback(wazuh_params, agent_params)
        result = WazuhAgent.perform_action_and_scan(agent_params, action_callback)
        logger.info(f'Pre and post uninstall checkfile comparison in {HostInformation.get_os_name_and_version_from_inventory(agent_params)}: {result}')
        WazuhAgent.assert_results(result)


    @staticmethod
    def assert_results(result) -> None:
        """
        Gets the status of an agent given its name.

        Args:
            result (dict): result of comparison between pre and post action scan

        """
        categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
        actions = ['added', 'modified', 'removed']
        # Testing the results
        for category in categories:
            for action in actions:
                assert result[category][action] == [], logger.error(f'{result[category][action]} was found in: {category}{action}')

    def areAgent_processes_active(agent_params):
        """
        Check if agent processes are active

        Args:
            agent_name (str): Agent name.

        Returns:
            str: Os name.
        """
        return bool([int(numero) for numero in Executor.execute_command(agent_params, 'pgrep wazuh').splitlines()])

    def isAgent_port_open(agent_params):
        """
        Check if agent port is open

        Args:
            agent_name (str): Agent name.

        Returns:
            str: Os name.
        """
        return 'ESTAB' in Executor.execute_command(agent_params, 'ss -t -a -n | grep ":1514" | grep ESTAB')

    def get_agents_information(wazuh_api: WazuhAPI) -> list:
        """
        Get information about agents.

        Returns:
            List: Information about agents.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents", headers=wazuh_api.headers, verify=False)

        try:
            return eval(response.text)['data']['affected_items']
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"


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
        try:
            agents_information = wazuh_api.get_agents_information()
            for element in agents_information:
                if element['id'] == identifier:
                    return [element['ip'], element['name'], element['status']]
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return [None, None, None]


    def get_agent_ip_status_and_name_by_id(wazuh_api: WazuhAPI, identifier):
        """
        Get IP status and name by ID.

        Args:
            identifier (str): Agent ID.

        Returns:
            List: IP, name, and status of the agent.
        """
        try:
            agents_information = wazuh_api.get_agents_information()
            for element in agents_information:
                if element['id'] == identifier:
                    return [element['ip'], element['name'], element['status']]
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return [None, None, None]


    def get_agent_os_version_by_name(wazuh_api: WazuhAPI, agent_name):
        """
        Get Agent os version by Agent name

        Args:
            agent_name (str): Agent name.

        Returns:
            str: Os version.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents", headers=wazuh_api.headers, verify=False)
        try:
            for agent_data in eval(response.text)['data']['affected_items']:
                if agent_data.get('name') == agent_name:
                    return agent_data.get('os', {}).get('version')
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"


    def get_agent_os_name_by_name(wazuh_api: WazuhAPI, agent_name):
        """
        Get Agent os name by Agent name

        Args:
            agent_name (str): Agent name.

        Returns:
            str: Os name.
        """
        response = requests.get(f"{wazuh_api.api_url}/agents", headers=wazuh_api.headers, verify=False)
        try:
            for agent_data in eval(response.text)['data']['affected_items']:
                if agent_data.get('name') == agent_name:
                    return 'suse' if agent_data.get('os', {}).get('name', '').lower() == 'sles' else agent_data.get('os', {}).get('name', '').lower()
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"
        return None


def add_agent_to_manager(wazuh_api: WazuhAPI, name, ip) -> str:
    """
    Add an agent to the manager.

    Args:
        wazuh_api (WazuhAPI): Instance of WazuhAPI class.
        name (str): Name of the agent.
        ip (str): IP address of the agent.

    Returns:
        str: Response text.
    """
    try:
        response = requests.post(f"{wazuh_api.api_url}/agents", json={"name": name, "ip": ip}, headers=wazuh_api.headers, verify=False)
        return response.text
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return f"Unexpected error: {e}"


def restart_agents(wazuh_api: WazuhAPI) -> str:
    """
    Restart agents.

    Args:
        wazuh_api (WazuhAPI): Instance of WazuhAPI class.

    Returns:
        str: Response text.
    """
    try:
        response = requests.put(f"{wazuh_api.api_url}/agents/restart", headers=wazuh_api.headers, verify=False)
        return response.text
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return f"Unexpected error: {e}"


def agent_status_report(wazuh_api: WazuhAPI) -> dict:
    """
    Get agent status report.

    Args:
        wazuh_api (WazuhAPI): Instance of WazuhAPI class.

    Returns:
        Dict: Agent status report.
    """
    try:
        response = requests.get(f"{wazuh_api.api_url}/agents/summary/status", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {}

