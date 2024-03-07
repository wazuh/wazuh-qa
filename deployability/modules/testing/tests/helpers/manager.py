from generic import HostInformation, HostConfiguration
from executor import Executor


class WazuhManager:
    def __init__(self):
        pass

    def install_manager(self, inventory_path):
        hostinformation = HostInformation()
        distribution = hostinformation.get_linux_distribution(inventory_path)
        commands = []
        print(distribution)
        if distribution == 'rpm' or distribution == 'opensuse-leap' or distribution == 'amzn':
            commands.extend([
                "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH",
                "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | sudo tee /etc/yum.repos.d/wazuh.repo",
                "yum -y install wazuh-manager"
            ])
        elif distribution == 'deb':
            commands.extend([
                "apt-get install gnupg apt-transport-https",
                "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg",
                'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list',
                "apt-get update",
                "apt-get -y install wazuh-manager"
            ])
        system_commands = [
                "systemctl daemon-reload",
                "systemctl enable wazuh-manager",
                "systemctl start wazuh-manager",
                "systemctl status wazuh-manager"
        ]

        commands.extend(system_commands)
        Executor.execute_commands(inventory_path, commands)

    def install_managers(self, inventories_paths=[]):
        for inventory in inventories_paths:
            self.install_manager(inventory)

    def uninstall_manager(self, inventory_path):
        hostinformation = HostInformation()
        distribution = hostinformation.get_linux_distribution(inventory_path)
        commands = []

        if distribution == 'rpm' or distribution == 'opensuse-leap' or distribution == 'amzn':
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
        Executor.execute_commands(inventory_path, commands)


    def uninstall_managers(self, inventories_paths=[]):
        for inventory in inventories_paths:
            self.uninstall_manager(inventory)
        


    def get_manager_status(self, inventory_path):
        """
        Stops the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager status
        """
        return Executor.execute_command(inventory_path, 'systemctl status wazuh-manager')


    def manager_stop(self, inventory_path):
        """
        Stops the manager

        Args:
            inventory_path: host's inventory path

        """
        Executor.execute_command(inventory_path, 'systemctl stop wazuh-manager')


    def manager_restart(self, inventory_path):
        """
        Restarts the manager

        Args:
            inventory_path: host's inventory path

        """
        Executor.execute_command(inventory_path, 'systemctl restart wazuh-manager')


    def manager_start(self, inventory_path):
        """
        Starts the manager

        Args:
            inventory_path: host's inventory path

        """
        Executor.execute_command(inventory_path, 'systemctl start wazuh-manager')


    def get_manager_version(self, inventory_path):
        """
        It returns the Manager versiom

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager version
        """
        return Executor.execute_command(inventory_path, '/var/ossec/bin/wazuh-control info -v')


    def get_manager_revision(self, inventory_path):
        """
        It returns the Manager revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Manager revision number
        """
        return Executor.execute_command(inventory_path, '/var/ossec/bin/wazuh-control info -r')


    def get_cluster_info(self, inventory_path):
        """
        It returns the cluster information

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Cluster status
        """
        return Executor.execute_command(inventory_path, '/var/ossec/bin/cluster_control -l')


    def get_agent_control_info(self, inventory_path):
        """
        It returns the Agent information from the manager

        Args:
            inventory_path: host's inventory path

        Returns:
            str: Agents status
        """
        return Executor.execute_command(inventory_path, '/var/ossec/bin/agent_control -l')


    def hasManagerClientKeys(self, inventory_path):
        """
        It returns the True of False depending if in the Manager Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        return 'true' in Executor.execute_command(inventory_path, '[ -f /var/ossec/etc/client.keys ] && echo true || echo false')


    def configuring_clusters(self, inventory_path, node_name, node_type, key, disabled):
        """
        It configures the cluster in ossec.conf

        Args:
            inventory_path: host's inventory path
            node_name: host's inventory path
            node_type: master/worker
            key: hexadecimal 16 key
            disabled: yes/no

        """
        commands = [
            f"sed -i 's/<node_name>node01<\/node_name>/<node_name>{node_name}<\/node_name>/' /var/ossec/etc/ossec.conf",
            f"sed -i 's/<node_type>master<\/node_type>/<node_type>{node_type}<\/node_type>/'  /var/ossec/etc/ossec.conf",
            f"sed -i 's/<key><\/key>/<key>{key}<\/key>/' /var/ossec/etc/ossec.conf",
            f"sed -i 's/<disabled>yes<\/disabled>/<disabled>{disabled}<\/disabled>/' /var/ossec/etc/ossec.conf",
            "systemctl restart wazuh-manager"
        ]
        Executor.execute_commands(inventory_path, commands)

#---------------------------------------------------

#inv = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
#print(WazuhManager().get_manager_revision(inv[1]))








#from agent import WazuhAgent
#from generic import CheckFiles
#checkfiles = CheckFiles()
#
##inventories_paths = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
##inventories_paths = ["/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
##inventories_paths = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
##inventories_paths = ["/tmp/dtt1-poc/manager-linux-debian-12-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-oracle-9-amd64/inventory.yaml"]
#inventories_paths = ["/tmp/dtt1-poc/manager-linux-ubuntu-16.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-centos-7-amd64/inventory.yaml"]
#
#maquina = 1
#
#
#def install_manager_callback():
#    WazuhManager().install_manager(inventories_paths[maquina])
#
#def uninstall_manager_callback():
#    WazuhManager().uninstall_manager(inventories_paths[maquina])
#
#def install_agent_callback():
#    WazuhAgent().install_agent(inventories_paths[maquina])
#
#def uninstall_agent_callback():
#    WazuhAgent().uninstall_agent(inventories_paths[maquina])
#
#result = checkfiles.perform_action_and_scan(inventories_paths[maquina], install_manager_callback)
#
##result = checkfiles.perform_action_and_scan(inventories_paths[maquina], uninstall_manager_callback)
#