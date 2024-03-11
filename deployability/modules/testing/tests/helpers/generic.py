import yaml
import chardet
import time
import re

from .executor import Executor
executor = Executor

class HostInformation:
    def __init__(self):
        pass
    
    def dir_exists(self, inventory_path, dir_path):
        """
        It returns the True of False depending if the directory exists

        Returns:
            str: type of host (windows, linux, macos)
        """
        return 'true' in executor.execute_command(inventory_path, f'test -d {dir_path} && echo "true" || echo "false"')


    def file_exists(self, inventory_path, file_path):
        """
        It returns the True of False depending if the file exists

        Returns:
            str: type of host (windows, linux, macos)
        """
        return 'true' in executor.execute_command(inventory_path, f'test -f {file_path} && echo "true" || echo "false"')


    def get_os_type(self, inventory_path):
        """
        It returns the os_type of host

        Returns:
            str: type of host (windows, linux, macos)
        """
        system = executor.execute_command(inventory_path, 'uname')
        return system.lower()


    def get_architecture(self, inventory_path):
        """
        It returns the arch of host


        Returns:
            str: arch (aarch64, x86_64, intel, apple)
        """
        return executor.execute_command(inventory_path, 'uname -m')


    def get_linux_distribution(self, inventory_path):
        """
        It returns the linux distribution of host

        Returns:
            str: linux distribution (deb, rpm, opensuse-leap, amazon)
        """
        os_name = re.search(r'/manager-linux-([^-]+)-', inventory_path).group(1)

        if os_name == 'ubuntu' or os_name == 'debian':
            linux_distribution = 'deb'
        else:
            linux_distribution = 'rpm'

        return linux_distribution


    def get_os_name_from_inventory(self, inventory_path):
        """
        It returns the linux os_name host inventory

        Returns:
            str: linux distribution (deb, rpm, opensuse-leap, amazon)
        """
        os_name = re.search(r'/manager-linux-([^-]+)-', inventory_path).group(1)

        return os_name

class HostConfiguration:
    def __init__(self):
        self.host_information = HostInformation()


    def sshd_config(self, inventory_path):
        commands = ["sudo sed -i '/^PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config", "sudo sed -i '/^PermitRootLogin no/s/^/#/' /etc/ssh/sshd_config", 'echo -e "PasswordAuthentication yes\nPermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config', 'sudo systemctl restart sshd', 'cat /etc/ssh/sshd_config']
        executor.execute_commands(inventory_path, commands)


    def disable_firewall(self, inventory_path):
        commands = ["sudo systemctl stop firewalld", "sudo systemctl disable firewalld"]
        executor.execute_commands(inventory_path, commands)


    def certs_create(self, wazuh_version, master_path, dashboard_path, indexer_paths=[], worker_paths=[] ):
        wazuh_version = '.'.join(wazuh_version.split('.')[:2])
        with open(master_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)
        master = inventory_data.get('ansible_host')

        with open(dashboard_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)
        dashboard = inventory_data.get('ansible_host')

        indexers = []
        for indexer_path in indexer_paths:
            with open(indexer_path, 'r') as yaml_file:
                inventory_data = yaml.safe_load(yaml_file)
            indexers.append(inventory_data.get('ansible_host'))

        workers = []
        for worker_path in worker_paths:
            with open(worker_path, 'r') as yaml_file:
                inventory_data = yaml.safe_load(yaml_file)
            workers.append(inventory_data.get('ansible_host'))

        ##Basic commands to setup the config file, add the ip for the master & dashboard
        os_name = self.host_information.get_os_name_from_inventory(master_path)
        print(os_name)
        if os_name == 'debian':
            commands = [
                f'wget https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh',
                f'wget https://packages.wazuh.com/{wazuh_version}/config.yml',
                "sed -i '/^\s*#/d' /home/vagrant/config.yml",
                """sed -i '/ip: "<wazuh-manager-ip>"/a\      node_type: master' /home/vagrant/config.yml""",
                f"sed -i '0,/<wazuh-manager-ip>/s//{master}/' /home/vagrant/config.yml",
                f"sed -i '0,/<dashboard-node-ip>/s//{dashboard}/' /home/vagrant/config.yml"
            ]
        else:
            commands = [
                f'curl -sO https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh',
                f'curl -sO https://packages.wazuh.com/{wazuh_version}/config.yml',
                "sed -i '/^\s*#/d' /home/vagrant/config.yml",
                """sed -i '/ip: "<wazuh-manager-ip>"/a\      node_type: master' /home/vagrant/config.yml""",
                f"sed -i '0,/<wazuh-manager-ip>/s//{master}/' /home/vagrant/config.yml",
                f"sed -i '0,/<dashboard-node-ip>/s//{dashboard}/' /home/vagrant/config.yml"
            ]

        # Adding workers
        for index, element in reversed(list(enumerate(workers))):
            commands.append(f'sed -i \'/node_type: master/a\\    - name: wazuh-{index+2}\\n      ip: "<wazuh-manager-ip>"\\n      node_type: worker\' /home/vagrant/config.yml')

        # Add as much indexers as indexer_paths were presented
        for index, element in enumerate(indexers, start=1):
            commands.append(f'sed -i \'/ip: "<indexer-node-ip>"/a\\    - name: node-{index+1}\\n      ip: "<indexer-node-ip>"\' /home/vagrant/config.yml')
            commands.append(f"""sed -i '0,/<indexer-node-ip>/s//{element}/' /home/vagrant/config.yml""")

        # Remove the last indexer due to previous existance of index-1 in the config
        for index, element in enumerate(indexers):
            if index == len(indexers) - 1:
                commands.append(f'''sed -i '/- name: node-{index+2}/,/^ *ip: "<indexer-node-ip>"/d' /home/vagrant/config.yml''')

        for index, element in enumerate(workers):
                commands.append(f"""sed -i '0,/<wazuh-manager-ip>/s//{element}/' /home/vagrant/config.yml""")

        ## Adding workers and indexer Ips
        certs_creation = [
            'bash wazuh-install.sh --generate-config-files --ignore-check'
        ]

        commands.extend(certs_creation)

        executor.execute_commands(master_path, commands)


    def scp_to(self, from_inventory_path, to_inventory_path):

        os_name = self.host_information.get_os_name_from_inventory(from_inventory_path)

        with open(to_inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        host = inventory_data.get('ansible_host')

        if os_name == 'ubuntu' or os_name == 'debian':
            commands = [
                "apt install sshpass",
                f"sshpass -p vagrant scp -o StrictHostKeyChecking=no /home/vagrant/wazuh-install-files.tar vagrant@{host}:/home/vagrant"
            ]
        elif os_name == 'amazon':
            commands = [
                "amazon-linux-extras install epel -y",
                "yum-config-manager --enable epel",
                "yum install -y sshpass",
                f"sshpass -p vagrant scp -o StrictHostKeyChecking=no /home/vagrant/wazuh-install-files.tar vagrant@{host}:/home/vagrant"
            ]
        else:
            commands = [
                "yum install -y sshpass",
                f"sshpass -p vagrant scp -o StrictHostKeyChecking=no /home/vagrant/wazuh-install-files.tar vagrant@{host}:/home/vagrant"
            ]

        executor.execute_commands(from_inventory_path, commands)


class HostMonitor:
    def __init__(self):
        pass


    def get_file_encoding(self, file_path: str) -> str:
        """Detect and return the file encoding.

        Args:
            file_path (str): File path to check.

        Returns:
            encoding (str): File encoding.
        """
        with open(file_path, 'rb') as f:
            data = f.read()
            if len(data) == 0:
                return 'utf-8'
            result = chardet.detect(data)
        return result['encoding']


    def file_monitor(self, monitored_file: str, target_string: str, timeout: int = 30) -> None:
        """
        Monitor a file for a specific string.

        Args:
            monitored_file (str): The file to monitor.
            target_string (str): The string to look for in the file.
            timeout (int, optional): The time to wait for the string to appear in the file. Defaults to 30.

        Returns:
            None: Returns None if the string is not found within the timeout.
            str: Returns the line containing the target string if found within the timeout.
        """
        encoding = self.get_file_encoding(monitored_file)

        # Check in the current file content for the string.
        with open(monitored_file, encoding=encoding) as _file:
            for line in _file:
                if target_string in line:
                    return line

        # Start count to set the timeout.
        start_time = time.time()

        # Start the file monitoring for future lines.
        with open(monitored_file, encoding=encoding) as _file:
            # Go to the end of the file.
            _file.seek(0, 2)
            while time.time() - start_time < timeout:
                current_position = _file.tell()
                line = _file.readline()

                if not line:
                    # No new line, wait for nex try.
                    _file.seek(current_position)
                    time.sleep(0.1)
                else:
                    # New line, check if the string matches.
                    if target_string in line:
                        return line


class CheckFiles:
    def __init__(self):
        self.initial_scan = []
        self.second_scan = []
        self.host_information = HostInformation()

    def perform_action_and_scan(self, inventory_path, callback):
        """
        Frame where check-file is taken before and after the callback
        Args:
            inventory_path (str): Inventory path
            callback (callback): callback that can modify the file directory
        Returns:
            dict: added and removed files
        """
        host_info = HostInformation()
        os_type = host_info.get_os_type(inventory_path)
        
        self.initial_scan = self._checkfiles(inventory_path, os_type)

        callback()

        self.second_scan = self._checkfiles(inventory_path, os_type)

        if self.initial_scan is None or self.second_scan is None:
            print("Error: Scans not performed.")
        set1 = set(self.initial_scan.strip().splitlines())
        set2 = set(self.second_scan.strip().splitlines())

        added_lines = list(set2 - set1)
        removed_lines = list(set1 - set2)

        changes = {
            'added': added_lines,
            'removed': removed_lines
        }

        return changes

    def _checkfiles(self, inventory_path, os_type):
        """
        It captures a structure of a /Var or c: directory status
        Returns:
            List: list of directories
        """
        if 'linux' in os_type or 'macos' in os_type:

            os_name = self.host_information.get_os_name_from_inventory(inventory_path)
            command = "sudo find /var -type f -o -type d 2>/dev/null | grep -v cache "

            os_commands = {
                'ubuntu': ['ubuntu', 'lxcfs', 'dpkg', 'PackageKit'],
                'centos': ['yum', 'rpm'],
                'redhat': ['yum', 'rpm'],
                'amazon': ['yum'],
                'debian': ['dpkg', 'lists', 'PackageKit', 'polkit-1', 'ucf', 'unattended', '.db', '.log'],
                'oracle': ['dnf', 'selinux'],
                'fedora': ['dnf', 'selinux', 'rpm'],
                'rocky_linux': ['dnf', 'selinux'],
            }

            os_command = os_commands.get(os_name)

            if os_command is not None:
                for i in os_command:
                    command += f" | grep -v {i}"
            else:
                print(f"Os name '{os_name}' not recognized.")

        elif 'windows' in os_type:
            command = 'dir /a-d /b /s | findstr /v /c:"\\.$" /c:"\\..$"| find /c ":"'
        else:
            print("Unsupported operating system.")

            return None

        return executor.execute_command(inventory_path, command)
