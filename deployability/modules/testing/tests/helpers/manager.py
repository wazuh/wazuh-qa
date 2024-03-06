from generic import HostInformation
from executor import Executor


class WazuhManager:
    def __init__(self):
        pass

    def install_manager(self, inventory_path):
        hostinformation = HostInformation()
        distribution = hostinformation.get_linux_distribution(inventory_path)

        if distribution == 'rpm':
            commands = [
                "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH",
                "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | sudo tee /etc/yum.repos.d/wazuh.repo",
                "yum -y install wazuh-manager"
            ]
        elif distribution == 'deb':
            commands = [
                "apt-get install gnupg apt-transport-https",
                "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg",
                'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list',
                "apt-get update",
                "apt-get -y install wazuh-manager"
            ]
        system_commands = [
                "systemctl daemon-reload",
                "systemctl enable wazuh-manager",
                "systemctl start wazuh-manager",
                "systemctl status wazuh-manager"
        ]

        commands.append(system_commands)
        Executor.execute_commands(inventory_path, commands)

    def install_managers(self, inventories_paths=[]):
        for inventory in inventories_paths:
            self.install_manager(inventory)

    def uninstall_manager(self, inventory_path):
        hostinformation = HostInformation()
        distribution = hostinformation.get_linux_distribution(inventory_path)

        if 'rpm' in distribution:
            commands = [
                "yum remove wazuh-manager -y",
                "rm -rf /var/ossec/"
            ]

        elif 'deb' in distribution:
            commands = [
                "apt-get remove --purge wazuh-manager -y"
            ]
        system_commands = [
                "systemctl disable wazuh-manager",
                "systemctl daemon-reload"
        ]

        commands.append(system_commands)
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












"""
    get_var_files=[
        "sudo find /var -type f -o -type d 2>/dev/null"
    ]


    initial_scan = None
    second_scan = None


#    for inven in inventories_paths:
#        for i in get_var_files:
#            result = Executor.execute_command(inven, i)
#            print(f"Command: {i}\nResult: {result}\n")
#            initial_scan = result
#            ruta_archivo = '/tmp/dtt1-poc/initial_scan.txt'
#            with open(ruta_archivo, 'w') as archivo:
#                archivo.write(initial_scan)
#
#
#
#    for inven in inventories_paths:
#        for i in install_manager_deb:
#            result = Executor.execute_command(inven, i)
#            print(f"Command: {i}\nResult: {result}\n")
#
#    for inven in inventories_paths:
#        for i in get_var_files:
#            result = Executor.execute_command(inven, i)
#            print(f"Command: {i}\nResult: {result}\n")
#            second_scan = result
#            ruta_archivo = '/tmp/dtt1-poc/second_scan.txt'
#            with open(ruta_archivo, 'w') as archivo:
#                archivo.write(second_scan)
#
#    if initial_scan is None or second_scan is None:
#        print("Error: Scans not performed.")
#        
#    set1 = set(initial_scan.strip().splitlines())
#    set2 = set(second_scan.strip().splitlines())
#
#    added_lines = set2 - set1
#    removed_lines = set1 - set2
#
#    changes = {
#            'added': added_lines,
#            'removed': removed_lines
#            }
#    #print(added_lines)
#    #print(removed_lines)
#    ruta_archivo = '/tmp/dtt1-poc/comparison.txt'
#    with open(ruta_archivo, 'w') as archivo:
#        archivo.write(str(changes))
#
#    for inven in inventories_paths:
#        for i in uninstall_manager_deb:
#            result = Executor.execute_command(inven, i)


    #inventories_paths = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
    inventories_paths = ["/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
    inventories_paths = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml"]
"""