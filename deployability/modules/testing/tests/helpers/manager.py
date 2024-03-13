from .generic import HostInformation, HostConfiguration
from .executor import Executor
from .constants import WAZUH_CONTROL, CLUSTER_CONTROL, AGENT_CONTROL, CLIENT_KEYS, WAZUH_CONF, WAZUH_ROOT

class WazuhManager:

    @staticmethod
    def install_manager(inventory_path, node_name, wazuh_version) -> None:
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
        for inventory in inventories_paths:
            for node_name in node_names:
                for wazuh_version in wazuh_versions:
                    WazuhManager.install_manager(inventory, node_name, wazuh_version)


    @staticmethod
    def uninstall_manager(inventory_path) -> None:
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
        for inventory in inventories_paths:
            WazuhManager.uninstall_manager(inventory)


    @staticmethod
    def get_manager_status(inventory_path) -> str:
        """
        Stops the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager status
        """

        return Executor.execute_command(inventory_path, 'systemctl status wazuh-manager')


    @staticmethod
    def manager_stop(inventory_path) -> None:
        """
        Stops the manager

        Args:
            inventory_path: host's inventory path

        """

        Executor.execute_command(inventory_path, 'systemctl stop wazuh-manager')


    @staticmethod
    def manager_restart(inventory_path) -> None:
        """
        Restarts the manager

        Args:
            inventory_path: host's inventory path

        """

        Executor.execute_command(inventory_path, 'systemctl restart wazuh-manager')


    @staticmethod
    def manager_start(inventory_path) -> None:
        """
        Starts the manager

        Args:
            inventory_path: host's inventory path

        """

        Executor.execute_command(inventory_path, 'systemctl start wazuh-manager')


    @staticmethod
    def get_manager_version(inventory_path) -> None:
        """
        It returns the Manager versiom

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager version
        """

        return Executor.execute_command(inventory_path, f'{WAZUH_CONTROL} info -v')


    @staticmethod
    def get_manager_revision(inventory_path) -> None:
        """
        It returns the Manager revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager revision number
        """

        return Executor.execute_command(inventory_path, f'{WAZUH_CONTROL} info -r')


    @staticmethod
    def get_cluster_info(inventory_path) -> None:
        """
        It returns the cluster information

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Cluster status
        """

        return Executor.execute_command(inventory_path, f'{CLUSTER_CONTROL} -l')


    @staticmethod
    def get_agent_control_info(inventory_path) -> None:
        """
        It returns the Agent information from the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Agents status
        """

        return Executor.execute_command(inventory_path, f'{AGENT_CONTROL} -l')


    @staticmethod
    def hasManagerClientKeys(inventory_path) -> bool:
        """
        It returns the True of False depending if in the Manager Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """

        return 'true' in Executor.execute_command(inventory_path, f'[ -f {CLIENT_KEYS} ] && echo true || echo false')


    @staticmethod
    def configuring_clusters(inventory_path, node_name, node_type, node_to_connect, key, disabled) -> None:
        """
        It configures the cluster in ossec.conf

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
