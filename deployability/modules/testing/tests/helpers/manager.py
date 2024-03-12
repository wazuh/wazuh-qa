from .generic import HostInformation, HostConfiguration
from .executor import Executor
import re

executor = Executor

class WazuhManager:
    def __init__(self):
        self.host_information = HostInformation()

    def install_manager(self, inventory_path, node_name, wazuh_version) -> None:
        wazuh_version = '.'.join(wazuh_version.split('.')[:2])
        os_name = self.host_information.get_os_name_from_inventory(inventory_path)
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

        executor.execute_commands(inventory_path, commands)

    def install_managers(self, inventories_paths=[], node_names=[], wazuh_versions=[]) -> None:
        for inventory in inventories_paths:
            for node_name in node_names:
                for wazuh_version in wazuh_versions:
                    self.install_manager(inventory, node_name, wazuh_version)

    def uninstall_manager(self, inventory_path) -> None:
        distribution = self.host_information.get_linux_distribution(inventory_path)
        commands = []

        if distribution == 'rpm':
            commands.extend([
                "yum remove wazuh-manager -y",
                "rm -rf /var/ossec/"
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

        executor.execute_commands(inventory_path, commands)


    def uninstall_managers(self, inventories_paths=[]) -> None:
        for inventory in inventories_paths:
            self.uninstall_manager(inventory)


    def get_manager_status(self, inventory_path) -> str:
        """
        Stops the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager status
        """

        return executor.execute_command(inventory_path, 'systemctl status wazuh-manager')


    def manager_stop(self, inventory_path) -> None:
        """
        Stops the manager

        Args:
            inventory_path: host's inventory path

        """

        executor.execute_command(inventory_path, 'systemctl stop wazuh-manager')


    def manager_restart(self, inventory_path) -> None:
        """
        Restarts the manager

        Args:
            inventory_path: host's inventory path

        """

        executor.execute_command(inventory_path, 'systemctl restart wazuh-manager')


    def manager_start(self, inventory_path) -> None:
        """
        Starts the manager

        Args:
            inventory_path: host's inventory path

        """

        executor.execute_command(inventory_path, 'systemctl start wazuh-manager')


    def get_manager_version(self, inventory_path) -> None:
        """
        It returns the Manager versiom

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager version
        """

        return executor.execute_command(inventory_path, '/var/ossec/bin/wazuh-control info -v')


    def get_manager_revision(self, inventory_path) -> None:
        """
        It returns the Manager revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager revision number
        """

        return executor.execute_command(inventory_path, '/var/ossec/bin/wazuh-control info -r')


    def get_cluster_info(self, inventory_path) -> None:
        """
        It returns the cluster information

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Cluster status
        """

        return executor.execute_command(inventory_path, '/var/ossec/bin/cluster_control -l')


    def get_agent_control_info(self, inventory_path) -> None:
        """
        It returns the Agent information from the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Agents status
        """

        return executor.execute_command(inventory_path, '/var/ossec/bin/agent_control -l')


    def hasManagerClientKeys(self, inventory_path) -> bool:
        """
        It returns the True of False depending if in the Manager Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """

        return 'true' in executor.execute_command(inventory_path, '[ -f /var/ossec/etc/client.keys ] && echo true || echo false')


    def configuring_clusters(self, inventory_path, node_name, node_type, node_to_connect, key, disabled) -> None:
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
            f"sed -i 's/<node_name>node01<\/node_name>/<node_name>{node_name}<\/node_name>/' /var/ossec/etc/ossec.conf",
            f"sed -i 's/<node_type>master<\/node_type>/<node_type>{node_type}<\/node_type>/'  /var/ossec/etc/ossec.conf",
            f"sed -i 's/<key><\/key>/<key>{key}<\/key>/' /var/ossec/etc/ossec.conf",
            f"sed -i 's/<node>NODE_IP<\/node>/<node>{node_to_connect}<\/node>/' /var/ossec/etc/ossec.conf",
            f"sed -i 's/<disabled>yes<\/disabled>/<disabled>{disabled}<\/disabled>/' /var/ossec/etc/ossec.conf",
            "systemctl restart wazuh-manager"
        ]

        executor.execute_commands(inventory_path, commands)
