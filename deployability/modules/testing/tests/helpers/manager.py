# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
import time

from .constants import CLUSTER_CONTROL, AGENT_CONTROL, WAZUH_CONF, WAZUH_ROOT, WAZUH_LOG
from .executor import WazuhAPI, ConnectionManager
from .generic import HostInformation, CheckFiles
from modules.testing.utils import logger
from .utils import Utils


class WazuhManager:

    @staticmethod
    def install_manager(inventory_path, node_name, wazuh_version, live) -> None:
        """
        Installs Wazuh Manager in the host

        Args:
            inventory_path (str): host's inventory path
            node_name (str): manager node name
            wazuh_version (str): major.minor.patch

        """
        os_name = HostInformation.get_os_name_from_inventory(inventory_path)

        if live == "False":
            s3_url = 'packages-dev.wazuh.com'
        else:
            s3_url = 'packages.wazuh.com'

        release = '.'.join(wazuh_version.split('.')[:2])

        logger.info(f'Installing the Wazuh manager with https://{s3_url}/{release}/wazuh-install.sh')

        if os_name == 'debian':
            commands = [
                    f"wget https://{s3_url}/{release}/wazuh-install.sh",
                    f"bash wazuh-install.sh --wazuh-server {node_name} --ignore-check"
            ]
        else:
            commands = [
                    f"curl -sO https://{s3_url}/{release}/wazuh-install.sh",
                    f"bash wazuh-install.sh --wazuh-server {node_name} --ignore-check"
            ]
        logger.info(f'Installing Manager in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        ConnectionManager.execute_commands(inventory_path, commands)


    @staticmethod
    def install_managers(inventories_paths=[], node_names=[], wazuh_versions=[]) -> None:
        """
        Install Wazuh Managers in the hosts

        Args:
            inventories_paths (list): list of hosts' inventory path
            node_name (list): managers node names' in the same order than inventories_paths
            wazuh_version (list): manager versions int he same order than inventories_paths

        """
        for inventory in inventories_paths:
            for node_name in node_names:
                for wazuh_version in wazuh_versions:
                    WazuhManager.install_manager(inventory, node_name, wazuh_version)


    @staticmethod
    def uninstall_manager(inventory_path) -> None:
        """
        Uninstall Wazuh Manager in the host

        Args:
            inventory_paths (str): hosts' inventory path
        """
        distribution = HostInformation.get_linux_distribution(inventory_path)
        commands = []

        if distribution == 'rpm':
            commands.extend([
                "yum remove wazuh-manager -y",
                f"rm -rf {WAZUH_ROOT}"
            ])
        elif distribution == 'deb':
            commands.extend([
                "apt-get remove --purge wazuh-manager -y"
            ])

        system_commands = [
                "systemctl disable wazuh-manager",
                "systemctl daemon-reload"
        ]

        commands.extend(system_commands)

        logger.info(f'Uninstalling Manager in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        ConnectionManager.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_managers(inventories_paths=[]) -> None:
        """
        Uninstall Wazuh Managers in the hosts

        Args:
            inventories_paths (list): list of hosts' inventory path
        """
        for inventory in inventories_paths:
            WazuhManager.uninstall_manager(inventory)


    @staticmethod
    def _install_manager_callback(wazuh_params, manager_name, manager_params):
        WazuhManager.install_manager(manager_params, manager_name, wazuh_params['wazuh_version'], wazuh_params['live'])


    @staticmethod
    def _uninstall_manager_callback(manager_params):
        WazuhManager.uninstall_manager(manager_params)


    @staticmethod
    def perform_action_and_scan(manager_params, action_callback) -> dict:
        """
        Takes scans using filters, the callback action and compares the result

        Args:
            manager_params (str): manager parameters
            callback (cb): callback (action)

        Returns:
            result (dict): comparison brief

        """
        result = CheckFiles.perform_action_and_scan(manager_params, action_callback)
        os_name = HostInformation.get_os_name_from_inventory(manager_params)
        logger.info(f'Applying filters in checkfiles in {HostInformation.get_os_name_and_version_from_inventory(manager_params)}')

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
    def perform_install_and_scan_for_manager(manager_params, manager_name, wazuh_params) -> None:
        """
        Coordinates the action of install the manager and compares the checkfiles

        Args:
            manager_params (str): manager parameters
            manager_name (str): manager name
            wazuh_params (str): wazuh parameters

        """
        action_callback = lambda: WazuhManager._install_manager_callback(wazuh_params, manager_name, manager_params)
        result = WazuhManager.perform_action_and_scan(manager_params, action_callback)
        logger.info(f'Pre and post install checkfile comparison in {HostInformation.get_os_name_and_version_from_inventory(manager_params)}: {result}')
        WazuhManager.assert_results(result, manager_params)


    @staticmethod
    def perform_uninstall_and_scan_for_manager(manager_params) -> None:
        """
        Coordinates the action of uninstall the manager and compares the checkfiles

        Args:
            manager_params (str): manager parameters

        """
        action_callback = lambda: WazuhManager._uninstall_manager_callback(manager_params)
        result = WazuhManager.perform_action_and_scan(manager_params, action_callback)
        logger.info(f'Pre and post uninstall checkfile comparison in {HostInformation.get_os_name_and_version_from_inventory(manager_params)}: {result}')
        WazuhManager.assert_results(result, manager_params)


    @staticmethod
    def assert_results(result) -> None:
        """
        Assert status of checkfiles

        Args:
            result (dict): result of comparison between pre and post action scan

        """
        categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
        actions = ['added', 'modified', 'removed']
        # Testing the results
        for category in categories:
            for action in actions:
                assert result[category][action] == [], logger.error(f'{result[category][action]} was found in: {category} {action}')


    @staticmethod
    def is_wazuh_api_port_open(inventory_path, wait=10, cycles=50) -> bool:
        """
        Check if the Wazuh manager API port is open
        Args:
            inventory_path (str): Wazuh manager inventory.
        Returns:
            bool: True if port is opened.
        """
        time.sleep(5)
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = ConnectionManager.execute_commands(inventory_path, 'ss -t -a -n | grep ":443"').get('output') or ""
            ports = ports.strip().split('\n')
            for port in ports:
                if any(state in port for state in ['ESTAB', 'LISTEN']):
                    continue
                else:
                    time.sleep(wait)
                    wait_cycles += 1
                    break
            else:
                return True
        return False

    @staticmethod
    def is_wazuh_agent_port_open(inventory_path, wait=10, cycles=50) -> bool:
        """
        Check if the Wazuh manager port is open
        Args:
            inventory_path (str): Manager inventory.

        Returns:
            bool: True if port is opened.
        """
        time.sleep(5)
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = ConnectionManager.execute_commands(inventory_path, 'ss -t -a -n | grep ":1514"').get('output') or ""
            ports = ports.strip().split('\n')
            for port in ports:
                if any(state in port for state in ['ESTAB', 'LISTEN']):
                    continue
                else:
                    time.sleep(wait)
                    wait_cycles += 1
                    break
            else:
                return True
        return False

    @staticmethod
    def is_wazuh_agent_enrollment_port_open(inventory_path, wait=10, cycles=50) -> bool:
        """
        Check if Wazuh manager's agent enrollment port is open
        Args:
            inventory_path (str): Manager inventory.

        Returns:
            bool: True if port is opened.
        """
        time.sleep(5)
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = ConnectionManager.execute_commands(inventory_path, 'ss -t -a -n | grep ":443"').get('output') or ""
            ports = ports.strip().split('\n')
            for port in ports:
                if any(state in port for state in ['ESTAB', 'LISTEN']):
                    continue
                else:
                    time.sleep(wait)
                    wait_cycles += 1
                    break
            else:
                return True
        return False

    @staticmethod
    def get_cluster_info(inventory_path) -> None:
        """
        Returns the Wazuh cluster information from the Wazuh manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Cluster status
        """

        return ConnectionManager.execute_commands(inventory_path, f'{CLUSTER_CONTROL} -l').get('output')


    @staticmethod
    def get_agent_control_info(inventory_path) -> None:
        """
        Returns the Agent information from the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Agents status
        """

        return ConnectionManager.execute_commands(inventory_path, f'{AGENT_CONTROL} -l').get('output')


    @staticmethod
    def configuring_clusters(inventory_path, node_name, node_type, node_to_connect_inventory, key, disabled) -> None:
        """
        Configures the cluster in ossec.conf

        Args:
            inventory_path: host's inventory path
            node_name: host's inventory path
            node_type: master/worker
            node_to_connect_inventory: inventory path of the node to connect
            key: hexadecimal 16 key
            disabled: yes/no

        """
        master_dns = Utils.extract_ansible_host(node_to_connect_inventory)
        commands = [
            f"sed -i 's/<node_name>node01<\/node_name>/<node_name>{node_name}<\/node_name>/' {WAZUH_CONF}",
            f"sed -i 's/<node_type>master<\/node_type>/<node_type>{node_type}<\/node_type>/'  {WAZUH_CONF}",
            f"sed -i 's/<key><\/key>/<key>{key}<\/key>/' {WAZUH_CONF}",
            f"sed -i 's/<node>NODE_IP<\/node>/<node>{HostInformation.get_internal_ip_from_aws_dns(master_dns)}<\/node>/' {WAZUH_CONF}",
            f"sed -i 's/<disabled>yes<\/disabled>/<disabled>{disabled}<\/disabled>/' {WAZUH_CONF}",
            "systemctl restart wazuh-manager"
        ]

        ConnectionManager.execute_commands(inventory_path, commands)
        if node_name in ConnectionManager.execute_commands(inventory_path, f'cat {WAZUH_CONF}').get('output'):
            logger.info(f'Cluster configured in: {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        else:
            logger.error(f'Error configuring cluster information in: {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')


    def get_manager_version(wazuh_api: WazuhAPI) -> str:
        """
        Get the version of the manager.

        Returns:
            str: The version of the manager.
        """
        try:
            response = requests.get(f"{wazuh_api.api_url}/?pretty=true", headers=wazuh_api.headers, verify=False)
            return eval(response.text)['data']['api_version']
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"


    def get_manager_revision(wazuh_api: WazuhAPI) -> str:
        """
        Get the revision of the manager.

        Returns:
            str: The revision of the manager.
        """
        try:
            response = requests.get(f"{wazuh_api.api_url}/?pretty=true", headers=wazuh_api.headers, verify=False)
            return eval(response.text)['data']['revision']
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"

    def get_manager_host_name(wazuh_api: WazuhAPI) -> str:
        """
        Get the hostname of the manager.

        Returns:
            str: The hostname of the manager.
        """
        try:
            response = requests.get(f"{wazuh_api.api_url}/?pretty=true", headers=wazuh_api.headers, verify=False)
            return eval(response.text)['data']['hostname']
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"


    def get_manager_nodes_status(wazuh_api: WazuhAPI) -> dict:
        """
        Get the status of the manager's nodes.

        Returns:
            Dict: The status of the manager's nodes.
        """
        try:
            response = requests.get(f"{wazuh_api.api_url}/manager/status", headers=wazuh_api.headers, verify=False)
            return eval(response.text)['data']['affected_items'][0]
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"

    def get_manager_logs(wazuh_api: WazuhAPI) -> list:
        """
        Get the logs of the manager.

        Returns:
            List: The logs of the manager.
        """
        try:
            response = requests.get(f"{wazuh_api.api_url}/manager/logs", headers=wazuh_api.headers, verify=False)
            return eval(response.text)['data']['affected_items']
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"

    @staticmethod
    def get_indexer_status(inventory_path) -> None:
        """
        Returns if Wazuh indexer is connected to Wazuh manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Agents status
        """

        indexerConnection = ConnectionManager.execute_commands(inventory_path, f'cat {WAZUH_LOG} | grep "IndexerConnector initialized successfully" | tail -n1').get('output')

        return indexerConnection is not None and indexerConnection.strip()
