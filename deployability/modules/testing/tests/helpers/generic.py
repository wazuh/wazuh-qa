import yaml
import chardet
import time
import re
import subprocess
from pathlib import Path
import os

from .executor import Executor
executor = Executor

class HostInformation:
    def __init__(self):
        pass
    
    def dir_exists(self, inventory_path, dir_path) -> str:
        """
        It returns the True of False depending if the directory exists

        Returns:
            str: type of host (windows, linux, macos)
        """
        return 'true' in executor.execute_command(inventory_path, f'test -d {dir_path} && echo "true" || echo "false"')


    def file_exists(self, inventory_path, file_path) -> bool:
        """
        It returns the True of False depending if the file exists

        Returns:
            bool: True or False
        """
        return 'true' in executor.execute_command(inventory_path, f'test -f {file_path} && echo "true" || echo "false"')


    def get_os_type(self, inventory_path) -> str:
        """
        It returns the os_type of host

        Returns:
            str: type of host (windows, linux, macos)
        """
        system = executor.execute_command(inventory_path, 'uname')
        return system.lower()


    def get_architecture(self, inventory_path) -> str:
        """
        It returns the arch of host


        Returns:
            str: arch (aarch64, x86_64, intel, apple)
        """
        return executor.execute_command(inventory_path, 'uname -m')


    def get_linux_distribution(self, inventory_path) -> str:
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


    def get_os_name_from_inventory(self, inventory_path) -> str:
        """
        It returns the linux os_name host inventory

        Returns:
            str: linux os name (debian, ubuntu, opensuse, amazon, centos, redhat)
        """
        os_name = re.search(r'/manager-linux-([^-]+)-', inventory_path).group(1)

        return os_name

class HostConfiguration:
    def __init__(self):
        self.host_information = HostInformation()


    def sshd_config(self, inventory_path) -> None:
        commands = ["sudo sed -i '/^PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config", "sudo sed -i '/^PermitRootLogin no/s/^/#/' /etc/ssh/sshd_config", 'echo -e "PasswordAuthentication yes\nPermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config', 'sudo systemctl restart sshd', 'cat /etc/ssh/sshd_config']
        executor.execute_commands(inventory_path, commands)


    def disable_firewall(self, inventory_path) -> None:
        commands = ["sudo systemctl stop firewalld", "sudo systemctl disable firewalld"]
        executor.execute_commands(inventory_path, commands)


    def certs_create(self, wazuh_version, master_path, dashboard_path, indexer_paths=[], worker_paths=[]) -> None:
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


    def scp_to(self, from_inventory_path, to_inventory_path, file_name) -> None:

        with open(from_inventory_path, 'r') as yaml_file:
            from_inventory_data = yaml.safe_load(yaml_file)

        with open(to_inventory_path, 'r') as yaml_file:
            to_inventory_data = yaml.safe_load(yaml_file)

        # Defining variables
        from_host = from_inventory_data.get('ansible_host')
        from_key = from_inventory_data.get('ansible_ssh_private_key_file')
        from_user = from_inventory_data.get('ansible_user')
        to_host = to_inventory_data.get('ansible_host')
        to_key = to_inventory_data.get('ansible_ssh_private_key_file')
        to_user = from_inventory_data.get('ansible_user')

        # Allowing handling permissions
        if file_name == 'wazuh-install-files.tar':
            executor.execute_command(from_inventory_path, f'chmod +rw {file_name}')

        # SCP
        subprocess.run(f'scp -i {from_key} -o StrictHostKeyChecking=no {from_user}@{from_host}:/home/vagrant/{file_name} {Path(__file__).parent}'  , shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subprocess.run(f'scp -i {to_key} -o StrictHostKeyChecking=no {Path(__file__).parent}/{file_name} {to_user}@{to_host}:/home/vagrant', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Restoring permissions
        if file_name == 'wazuh-install-files.tar':
            executor.execute_command(from_inventory_path, f'chmod 600 {file_name}')
            executor.execute_command(to_inventory_path, f'chmod 600 {file_name}')

        # Deleting file from localhost
        file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), file_name)

        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"The file {file_name} has been deleted.")
        else:
            print(f"The file {file_name} does not exist.")


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

    def _checkfiles(self, inventory_path, os_type, directory, hash_algorithm='sha256') -> dict:
        """
        It captures a structure of a directory
        Returns:
            Dict: dict of directories:hash
        """

        if 'linux' in os_type or 'macos' in os_type:

            command = f'sudo find {directory} -type f -exec sha256sum {{}} +'

            result = executor.execute_command(inventory_path, command)

        elif 'windows' in os_type:
            command = 'dir /a-d /b /s | findstr /v /c:"\\.$" /c:"\\..$"| find /c ":"'
        else:
            print("Unsupported operating system.")
            return None
        snapshot = {}
        for line in result.splitlines():
            hash_value, file_path = line.split(maxsplit=1)
            snapshot[file_path] = hash_value

        return snapshot

    def _perform_scan(self, inventory_path, os_type, directories):
        return {directory: self._checkfiles(inventory_path, os_type, directory) for directory in directories}

    def _calculate_changes(self, initial_scan, second_scan):
        added_files = list(set(second_scan) - set(initial_scan))
        removed_files = list(set(initial_scan) - set(second_scan))
        modified_files = [path for path in set(initial_scan) & set(second_scan) if initial_scan[path] != second_scan[path]]
        return {'added': added_files, 'removed': removed_files, 'modified': modified_files}

    def perform_action_and_scan(self, inventory_path, callback) -> dict:
        host_info = HostInformation()
        os_type = host_info.get_os_type(inventory_path)

        directories = ['/boot', '/usr/bin', '/root', '/usr/sbin']

        initial_scans = self._perform_scan(inventory_path, os_type, directories)

        callback()

        second_scans = self._perform_scan(inventory_path, os_type, directories)

        changes = {directory: self._calculate_changes(initial_scans[directory], second_scans[directory]) for directory in directories}

        return changes

