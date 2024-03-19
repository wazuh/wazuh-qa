import requests
from .generic import HostInformation, HostConfiguration
from .executor import Executor, WazuhAPI
from .constants import WAZUH_CONTROL, CLUSTER_CONTROL, AGENT_CONTROL, CLIENT_KEYS, WAZUH_CONF, WAZUH_ROOT

class WazuhManager:

    @staticmethod
    def install_manager(inventory_path, node_name, wazuh_version) -> None:
        """
        Installs Wazuh Manager in the host

        Args:
            inventory_path (str): host's inventory path
            node_name (str): manager node name
            wazuh_version (str): major.minor.patch

        """
        wazuh_version = '.'.join(wazuh_version.split('.')[:2])
        os_name = HostInformation.get_os_name_from_inventory(inventory_path)

        if os_name == 'debian':
            commands = [
                    f"wget https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh",
                    f"bash wazuh-install.sh --wazuh-server {node_name} --ignore-check"
            ]
        else:
            commands = [
                    f"curl -sO https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh",
                    f"bash wazuh-install.sh --wazuh-server {node_name} --ignore-check"
            ] 

        Executor.execute_commands(inventory_path, commands)


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
        Unnstall Wazuh Manager in the host

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

        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_managers(inventories_paths=[]) -> None:
        """
        Unnstall Wazuh Managers in the hosts

        Args:
            inventories_paths (list): list of hosts' inventory path
        """
        for inventory in inventories_paths:
            WazuhManager.uninstall_manager(inventory)


    @staticmethod
    def get_cluster_info(inventory_path) -> None:
        """
        Returns the cluster information

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Cluster status
        """

        return Executor.execute_command(inventory_path, f'{CLUSTER_CONTROL} -l')


    @staticmethod
    def get_agent_control_info(inventory_path) -> None:
        """
        Returns the Agent information from the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Agents status
        """

        return Executor.execute_command(inventory_path, f'{AGENT_CONTROL} -l')


    @staticmethod
    def configuring_clusters(inventory_path, node_name, node_type, node_to_connect, key, disabled) -> None:
        """
        Configures the cluster in ossec.conf

        Args:
            inventory_path: host's inventory path
            node_name: host's inventory path
            node_type: master/worker
            node_to_connect: master/worker
            key: hexadecimal 16 key
            disabled: yes/no

        """
        commands = [
            f"sed -i 's/<node_name>node01<\/node_name>/<node_name>{node_name}<\/node_name>/' {WAZUH_CONF}",
            f"sed -i 's/<node_type>master<\/node_type>/<node_type>{node_type}<\/node_type>/'  {WAZUH_CONF}",
            f"sed -i 's/<key><\/key>/<key>{key}<\/key>/' {WAZUH_CONF}",
            f"sed -i 's/<node>NODE_IP<\/node>/<node>{node_to_connect}<\/node>/' {WAZUH_CONF}",
            f"sed -i 's/<disabled>yes<\/disabled>/<disabled>{disabled}<\/disabled>/' {WAZUH_CONF}",
            "systemctl restart wazuh-manager"
        ]

        Executor.execute_commands(inventory_path, commands)

## ----------- api

    def get_manager_version(wazuh_api: WazuhAPI) -> str:
        """
        Get the version of the manager.

        Returns:
            str: The version of the manager.
        """
        response = requests.get(f"{wazuh_api.api_url}/?pretty=true", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['api_version']


    def get_manager_revision(wazuh_api: WazuhAPI) -> str:
        """
        Get the revision of the manager.

        Returns:
            str: The revision of the manager.
        """
        response = requests.get(f"{wazuh_api.api_url}/?pretty=true", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['revision']


    def get_manager_host_name(wazuh_api: WazuhAPI) -> str:
        """
        Get the hostname of the manager.

        Returns:
            str: The hostname of the manager.
        """
        response = requests.get(f"{wazuh_api.api_url}/?pretty=true", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['hostname']


    def get_manager_nodes_status(wazuh_api: WazuhAPI) -> dict:
        """
        Get the status of the manager's nodes.

        Returns:
            Dict: The status of the manager's nodes.
        """
        response = requests.get(f"{wazuh_api.api_url}/manager/status", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['affected_items'][0]


    def get_manager_logs(wazuh_api: WazuhAPI) -> list:
        """
        Get the logs of the manager.

        Returns:
            List: The logs of the manager.
        """
        response = requests.get(f"{wazuh_api.api_url}/manager/logs", headers=wazuh_api.headers, verify=False)
        return eval(response.text)['data']['affected_items']
