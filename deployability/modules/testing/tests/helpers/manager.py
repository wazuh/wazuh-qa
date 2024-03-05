from executor import Executor
from generic import HostInformation

def install_manager(inventory_path):
    hostinformation = HostInformation()
    distribution = hostinformation.get_linux_distribution(inventory_path)

    if distribution == 'rpm':
        commands = [
            "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH",
            "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | sudo tee /etc/yum.repos.d/wazuh.repo",
            "yum -y install wazuh-manager",
            "systemctl daemon-reload",
            "systemctl enable wazuh-manager",
            "systemctl start wazuh-manager",
            "systemctl status wazuh-manager"
        ]
    elif distribution == 'deb':
        commands = [
            "apt-get install gnupg apt-transport-https",
            "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg",
            'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list',
            "apt-get update",
            "apt-get -y install wazuh-manager",
            "systemctl daemon-reload",
            "systemctl enable wazuh-manager",
            "systemctl start wazuh-manager",
            "systemctl status wazuh-manager"
        ]
    Executor.execute_commands(inventory_path, commands)

def install_managers(inventories_paths=[]):
    for inventory in inventories_paths:
        install_manager(inventory)

def uninstall_manager(inventory_path):
    hostinformation = HostInformation()
    distribution = hostinformation.get_linux_distribution(inventory_path)

    if 'rpm' in distribution:
        commands = [
            "yum remove wazuh-manager -y",
            "rm -rf /var/ossec/",
            "systemctl disable wazuh-manager",
            "systemctl daemon-reload"
        ]

    elif 'deb' in distribution:
        commands = [
            "apt-get remove --purge wazuh-manager -y",
            "systemctl disable wazuh-manager",
            "systemctl daemon-reload"
        ]
    Executor.execute_commands(inventory_path, commands)

def uninstall_managers(inventories_paths=[]):
    for inventory in inventories_paths:
        uninstall_manager(inventory)
        


#---------------------------------------------------

inv = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
uninstall_managers(inv)












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