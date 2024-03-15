import yaml
import chardet
import time
import re
import subprocess
from pathlib import Path
import os
from .executor import Executor

from .constants import WAZUH_CONTROL, CLUSTER_CONTROL, AGENT_CONTROL, CLIENT_KEYS, WAZUH_CONF, WAZUH_ROOT


class HostInformation:

    @staticmethod
    def dir_exists(inventory_path, dir_path) -> str:
        """
        It returns the True of False depending if the directory exists

        Args:
            inventory_path: host's inventory path
            dir_path: path of the directory to be checked

        Returns:
            str: type of host (windows, linux, macos)
        """
        return 'true' in Executor.execute_command(inventory_path, f'test -d {dir_path} && echo "true" || echo "false"')


    @staticmethod
    def file_exists(inventory_path, file_path) -> bool:
        """
        It returns the True of False depending if the file exists

        Args:
            inventory_path: host's inventory path
            file_path: path of the file to be checked

        Returns:
            bool: True or False
        """
        return 'true' in Executor.execute_command(inventory_path, f'test -f {file_path} && echo "true" || echo "false"')


    @staticmethod
    def get_os_type(inventory_path) -> str:
        """
        It returns the os_type of host

        Args:
            inventory_path: host's inventory path

        Returns:
            str: type of host (windows, linux, macos)
        """
        system = Executor.execute_command(inventory_path, 'uname')
        return system.lower()


    @staticmethod
    def get_architecture(inventory_path) -> str:
        """
        It returns the arch of host

        Args:
            inventory_path: host's inventory path

        Returns:
            str: arch (aarch64, x86_64, intel, apple)
        """
        return Executor.execute_command(inventory_path, 'uname -m')


    @staticmethod
    def get_linux_distribution(inventory_path) -> str:
        """
        It returns the linux distribution of host

        Args:
            inventory_path: host's inventory path

        Returns:
            str: linux distribution (deb, rpm, opensuse-leap, amazon)
        """
        os_name = re.search(r'/manager-linux-([^-]+)-', inventory_path).group(1)

        if os_name == 'ubuntu' or os_name == 'debian':
            linux_distribution = 'deb'
        else:
            linux_distribution = 'rpm'

        return linux_distribution


    @staticmethod
    def get_os_name_from_inventory(inventory_path) -> str:
        """
        It returns the linux os_name host inventory

        Args:
            inventory_path: host's inventory path

        Returns:
            str: linux os name (debian, ubuntu, opensuse, amazon, centos, redhat)
        """
        os_name = re.search(r'/manager-linux-([^-]+)-', inventory_path).group(1)

        return os_name

    @staticmethod
    def get_current_dir(inventory_path) -> str:
        """
        It returns the current directory

        Args:
            inventory_path: host's inventory path

        Returns:
            str: current directory
        """
        return Executor.execute_command(inventory_path, 'pwd')

class HostConfiguration:

    @staticmethod
    def sshd_config(inventory_path) -> None:
        commands = ["sudo sed -i '/^PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config", "sudo sed -i '/^PermitRootLogin no/s/^/#/' /etc/ssh/sshd_config", 'echo -e "PasswordAuthentication yes\nPermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config', 'sudo systemctl restart sshd', 'cat /etc/ssh/sshd_config']
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def disable_firewall(inventory_path) -> None:
        commands = ["sudo systemctl stop firewalld", "sudo systemctl disable firewalld"]
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def certs_create(wazuh_version, master_path, dashboard_path, indexer_paths=[], worker_paths=[]) -> None:
        current_directory = HostInformation.get_current_dir(master_path).replace("\n","")

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
        os_name = HostInformation.get_os_name_from_inventory(master_path)
        if os_name == 'debian':
            commands = [
                f'wget https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh',
                f'wget https://packages.wazuh.com/{wazuh_version}/config.yml',
                f"sed -i '/^\s*#/d' {current_directory}/config.yml",
                f"""sed -i '/ip: "<wazuh-manager-ip>"/a\      node_type: master' {current_directory}/config.yml""",
                f"sed -i '0,/<wazuh-manager-ip>/s//{master}/' {current_directory}/config.yml",
                f"sed -i '0,/<dashboard-node-ip>/s//{dashboard}/' {current_directory}/config.yml"
            ]
        else:
            commands = [
                f'curl -sO https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh',
                f'curl -sO https://packages.wazuh.com/{wazuh_version}/config.yml',
                f"sed -i '/^\s*#/d' {current_directory}/config.yml",
                f"""sed -i '/ip: "<wazuh-manager-ip>"/a\      node_type: master' {current_directory}/config.yml""",
                f"sed -i '0,/<wazuh-manager-ip>/s//{master}/' {current_directory}/config.yml",
                f"sed -i '0,/<dashboard-node-ip>/s//{dashboard}/' {current_directory}/config.yml"
            ]

        # Adding workers
        for index, element in reversed(list(enumerate(workers))):
            commands.append(f'sed -i \'/node_type: master/a\\    - name: wazuh-{index+2}\\n      ip: "<wazuh-manager-ip>"\\n      node_type: worker\' {current_directory}/config.yml')

        # Add as much indexers as indexer_paths were presented
        for index, element in enumerate(indexers, start=1):
            commands.append(f'sed -i \'/ip: "<indexer-node-ip>"/a\\    - name: node-{index+1}\\n      ip: "<indexer-node-ip>"\' {current_directory}/config.yml')
            commands.append(f"""sed -i '0,/<indexer-node-ip>/s//{element}/' {current_directory}/config.yml""")

        # Remove the last indexer due to previous existance of index-1 in the config
        for index, element in enumerate(indexers):
            if index == len(indexers) - 1:
                commands.append(f'''sed -i '/- name: node-{index+2}/,/^ *ip: "<indexer-node-ip>"/d' {current_directory}/config.yml''')

        for index, element in enumerate(workers):
                commands.append(f"""sed -i '0,/<wazuh-manager-ip>/s//{element}/' {current_directory}/config.yml""")

        ## Adding workers and indexer Ips
        certs_creation = [
            'bash wazuh-install.sh --generate-config-files --ignore-check'
        ]

        commands.extend(certs_creation)
        Executor.execute_commands(master_path, commands)


    @staticmethod
    def scp_to(from_inventory_path, to_inventory_path, file_name) -> None:
        current_from_directory = HostInformation.get_current_dir(from_inventory_path).replace("\n","")
        current_to_directory = HostInformation.get_current_dir(to_inventory_path).replace("\n","")
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
            Executor.execute_command(from_inventory_path, f'chmod +rw {file_name}')

        # SCP
        subprocess.run(f'scp -i {from_key} -o StrictHostKeyChecking=no {from_user}@{from_host}:{current_from_directory}/{file_name} {Path(__file__).parent}'  , shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subprocess.run(f'scp -i {to_key} -o StrictHostKeyChecking=no {Path(__file__).parent}/{file_name} {to_user}@{to_host}:{current_to_directory}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Restoring permissions
        if file_name == 'wazuh-install-files.tar':
            Executor.execute_command(from_inventory_path, f'chmod 600 {file_name}')
            Executor.execute_command(to_inventory_path, f'chmod 600 {file_name}')

        # Deleting file from localhost
        file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), file_name)

        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"The file {file_name} has been deleted.")
        else:
            print(f"The file {file_name} does not exist.")


class HostMonitor:

    @staticmethod
    def get_file_encoding(file_path: str) -> str:
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


    @staticmethod
    def file_monitor(monitored_file: str, target_string: str, timeout: int = 30) -> None:
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
        encoding = HostMonitor.get_file_encoding(monitored_file)

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

    @staticmethod
    def _checkfiles(inventory_path, os_type, directory, filter= None, hash_algorithm='sha256') -> dict:
        """
        It captures a structure of a directory
        Returns:
            Dict: dict of directories:hash
        """
        if 'linux' in os_type or 'macos' in os_type:

            command = f'sudo find {directory} -type f -exec sha256sum {{}} + {filter}'

            result = Executor.execute_command(inventory_path, command)

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


    @staticmethod
    def _perform_scan(inventory_path, os_type, directories, filters):
        return {directory: CheckFiles._checkfiles(inventory_path, os_type, directory, filters) for directory in directories}


    @staticmethod
    def _calculate_changes(initial_scan, second_scan):
        added_files = list(set(second_scan) - set(initial_scan))
        removed_files = list(set(initial_scan) - set(second_scan))
        modified_files = [path for path in set(initial_scan) & set(second_scan) if initial_scan[path] != second_scan[path]]
        return {'added': added_files, 'removed': removed_files, 'modified': modified_files}


    @staticmethod
    def perform_action_and_scan(inventory_path, callback) -> dict:
        os_type = HostInformation.get_os_type(inventory_path)

        directories = ['/boot', '/usr/bin', '/root', '/usr/sbin']
        filters_keywords = ['grep', 'tar', 'coreutils', 'sed', 'procps', 'gawk', 'lsof', 'curl', 'openssl', 'libcap', 'apt-transport-https', 'libcap2-bin', 'software-properties-common', 'gnupg', 'gpg']
        filters = f"| grep -v {filters_keywords[0]}"

        for filter_ in filters_keywords[1:]:
            filters+= f" | grep -v {filter_}"

        initial_scans = CheckFiles._perform_scan(inventory_path, os_type, directories, filters)

        callback()

        second_scans = CheckFiles._perform_scan(inventory_path, os_type, directories, filters)

        changes = {directory: CheckFiles._calculate_changes(initial_scans[directory], second_scans[directory]) for directory in directories}

        return changes

class GeneralComponentActions:

    @staticmethod
    def get_component_status(inventory_path, host_role) -> str:
        """
        Return the host status

        Args:
            inventory_path: host's inventory path
            host_role: role of the component

        Returns:
            str: Role status
        """

        return Executor.execute_command(inventory_path, f'systemctl status {host_role}')


    @staticmethod
    def component_stop(inventory_path, host_role) -> None:
        """
        Stops the component

        Args:
            inventory_path: host's inventory path
            host_role: role of the component

        """

        Executor.execute_command(inventory_path, f'systemctl stop {host_role}')


    @staticmethod
    def component_restart(inventory_path, host_role) -> None:
        """
        Restarts the component

        Args:
            inventory_path: host's inventory path
            host_role: role of the component

        """

        Executor.execute_command(inventory_path, f'systemctl restart {host_role}')


    @staticmethod
    def component_start(inventory_path, host_role) -> None:
        """
        Starts the component

        Args:
            inventory_path: host's inventory path
            host_role: role of the component

        """

        Executor.execute_command(inventory_path, f'systemctl restart {host_role}')


    @staticmethod
    def get_component_version(inventory_path) -> str:
        """
        It returns the installed component version

        Args:
            inventory_path: host's inventory path

        Returns:
            str: version
        """
        return Executor.execute_command(inventory_path, f'{WAZUH_CONTROL} info -v')


    @staticmethod
    def get_component_revision(inventory_path) -> str:
        """
        It returns the Agent revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: revision number
        """
        return Executor.execute_command(inventory_path, f'{WAZUH_CONTROL} info -r')


    @staticmethod
    def hasAgentClientKeys(inventory_path) -> bool:
        """
        It returns the True of False depending if in the component Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        return 'true' in Executor.execute_command(inventory_path, f'[ -f {CLIENT_KEYS} ] && echo true || echo false')


    @staticmethod
    def isComponentActive(inventory_path, host_role) -> bool:
        """
        It returns the True of False depending if the component is Active

        Args:
            inventory_path: host's inventory path
            host_role: role of the component

        Returns:
            bool: True/False
        """
        return Executor.execute_command(inventory_path, f'systemctl is-active {host_role}') == 'active'
