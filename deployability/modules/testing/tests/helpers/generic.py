from executor import Executor
import yaml


class HostInformation:
    def __init__(self):
        pass
    
    def dir_exists(self, inventory_path, dir_path):
        """
        It returns the True of False depending if the directory exists

        Returns:
            str: type of host (windows, linux, macos)
        """
        result = Executor.execute_command(inventory_path, f'test -d {dir_path} && echo "true" || echo "false"')
        if 'false' in result:
            result = False
        else:
            result = True
        return result

    def file_exists(self, inventory_path, file_path):
        """
        It returns the True of False depending if the file exists

        Returns:
            str: type of host (windows, linux, macos)
        """
        result = Executor.execute_command(inventory_path, f'test -f {file_path} && echo "true" || echo "false"')
        if 'false' in result:
            result = False
        else:
            result = True
        return result

    def get_os_type(self, inventory_path):
        """
        It returns the os_type of host

        Returns:
            str: type of host (windows, linux, macos)
        """
        system = Executor.execute_command(inventory_path, 'uname')
        return system.lower()
    
    def get_architecture(self, inventory_path):
        """
        It returns the arch of host

        Returns:
            str: arch (aarch64, x86_64, intel, apple)
        """
        return Executor.execute_command(inventory_path, 'uname -m')

    def get_linux_distribution(self, inventory_path):
        """
        It returns the linux distribution of host

        Returns:
            str: linux distribution (deb, rpm)
        """
        if 'linux' in self.get_os_type(inventory_path):
            package_managers = {
                '/etc/debian_version': 'deb',
                '/etc/redhat-release': 'rpm',
            }
            for file_path, package_manager in package_managers.items():
                if self.file_exists(inventory_path, file_path):
                    return package_manager



class HostConfiguration:
    def __init__(self):
        pass
    
    def sshd_config(self, inventory_path):
        commands = ["sudo sed -i '/^PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config", "sudo sed -i '/^PermitRootLogin no/s/^/#/' /etc/ssh/sshd_config", 'echo -e "PasswordAuthentication yes\nPermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config', 'sudo systemctl restart sshd', 'cat /etc/ssh/sshd_config']
        Executor.execute_commands(inventory_path, commands)

    def disable_firewall(self, inventory_path):
        commands = ["sudo systemctl stop firewalld", "sudo systemctl disable firewalld"]
        Executor.execute_commands(inventory_path, commands)

    def certs_create(self, inventory_path):
        commands = [
            'curl -sO https://packages.wazuh.com/4.7/wazuh-certs-tool.sh',
            'curl -sO https://packages.wazuh.com/4.7/config.yml',
            "sed -i '0,/#  node_type: worker/s/#  node_type:/  node_type:/' /home/vagrant/config.yml",
            "sed -i '0,/#  ip: \"<wazuh-manager-ip>\"/ s/#  ip: \"<wazuh-manager-ip>\"/     ip: \"<wazuh-manager-ip>\"/' /home/vagrant/config.yml",
            "sed -i 's/^ *#- name: wazuh-2/    - name: wazuh-2/' /home/vagrant/config.yml",
            "sed -i '0,/<wazuh-manager-ip>/s//192.168.57.2/' /home/vagrant/config.yml",
            "sed -i '0,/<wazuh-manager-ip>/s//192.168.57.3/' /home/vagrant/config.yml",
            "sed -i '0,/<indexer-node-ip>/s//192.168.57.2/' /home/vagrant/config.yml",
            "sed -i '0,/<dashboard-node-ip>/s//192.168.57.2/' /home/vagrant/config.yml",
            'bash /home/vagrant/wazuh-certs-tool.sh -A',
            'tar -cvf /home/vagrant/wazuh-certificates.tar -C /home/vagrant/wazuh-certificates/ .',
            'rm -rf /home/vagrant/wazuh-certificates'
        ]
        Executor.execute_commands(inventory_path, commands)

    def scp_to(self, from_inventory_path, to_inventory_path):
        hostinformation = HostInformation()
        distribution = hostinformation.get_linux_distribution(from_inventory_path)

        with open(to_inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        host = inventory_data.get('ansible_host')
    
        if 'deb' in distribution:
            commands = [
                "apt install sshpass",
                f"sshpass -p vagrant scp -o StrictHostKeyChecking=no /home/vagrant/wazuh-certificates.tar vagrant@{host}:/home/vagrant"
            ]
        elif 'rpm' in distribution:
            commands = [
                "yum install -y sshpass",
                f"sshpass -p vagrant scp -o StrictHostKeyChecking=no /home/vagrant/wazuh-certificates.tar vagrant@{host}:/home/vagrant"
            ]

        Executor.execute_commands(from_inventory_path, commands)
        
#-----------------------------
inv = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]

hostconfig_= HostConfiguration()
hostconfig_.scp_to(inv[0], inv[1])
