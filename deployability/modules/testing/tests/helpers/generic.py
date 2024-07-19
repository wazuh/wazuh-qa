# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import boto3
import chardet
import os
import re
import socket
import subprocess
import time
import yaml

from pathlib import Path
from .constants import WAZUH_CONTROL, CLIENT_KEYS, WINDOWS_CLIENT_KEYS, WINDOWS_VERSION, WINDOWS_REVISION, MACOS_WAZUH_CONTROL, MACOS_CLIENT_KEYS
from .executor import ConnectionManager
from modules.testing.utils import logger
from .utils import Utils


class HostInformation:

    @staticmethod
    def dir_exists(inventory_path, dir_path) -> str:
        """
        It returns the True of False depending if the directory exists

        Args:
            inventory_path: host's inventory path
            dir_path: path of the directory to be checked

        Returns:
            bool: True or False
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            return 'True' in ConnectionManager.execute_commands(inventory_path, f'test -d {dir_path} && echo "True" || echo "False"').get('output')

        elif os_type == 'windows':
            result = ConnectionManager.execute_commands(inventory_path, f'Test-Path -Path "{dir_path}"')
            if result.get('success'):
                return 'True' in result.get('output')

        elif os_type == 'macos':
            return 'true' in ConnectionManager.execute_commands(inventory_path, f'stat {dir_path} >/dev/null 2>&1 && echo "true" || echo "false"').get('output')

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
        os_type = HostInformation.get_os_type(inventory_path)
        if os_type == 'linux':
            return ConnectionManager.execute_commands(inventory_path, f'test -f {file_path} && echo "True" || echo "False"').get('output')
        elif os_type == 'windows':
            return ConnectionManager.execute_commands(inventory_path, f'Test-Path -Path "{file_path}"').get('output')
        elif os_type == 'macos':
            return 'true' in ConnectionManager.execute_commands(inventory_path, f'stat {file_path} >/dev/null 2>&1 && echo "true" || echo "false"').get('output')

    @staticmethod
    def get_os_type(inventory_path) -> str:
        """
        It returns the os_type of host

        Args:
            inventory_path: host's inventory path

        Returns:
            str: type of host (windows, linux, macos)
        """
        try:
            with open(inventory_path.replace('inventory', 'track'), 'r') as file:
                data = yaml.safe_load(file)
            if 'platform' in data:
                return data['platform']
            else:
                raise KeyError("The 'platform' key was not found in the YAML file.")
        except FileNotFoundError:
            logger.error(f"The YAML file '{inventory_path}' was not found.")
        except yaml.YAMLError as e:
            logger.error(f"Error while loading the YAML file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")


    @staticmethod
    def get_architecture(inventory_path) -> str:
        """
        It returns the arch of host

        Args:
            inventory_path: host's inventory path

        Returns:
            str: architecture (amd64, arm64)
        """
        try:
            with open(inventory_path.replace('inventory', 'track'), 'r') as file:
                data = yaml.safe_load(file)
            if 'platform' in data:
                return data['arch']
            else:
                raise KeyError("The 'platform' key was not found in the YAML file.")
        except FileNotFoundError:
            logger.error(f"The YAML file '{inventory_path}' was not found.")
        except yaml.YAMLError as e:
            logger.error(f"Error while loading the YAML file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")


    @staticmethod
    def get_linux_distribution(inventory_path) -> str:
        """
        It returns the linux distribution of host

        Args:
            inventory_path: host's inventory path

        Returns:
            str: linux distribution (deb, rpm)
        """
        if 'manager' in inventory_path:
            os_name = re.search(r'/manager-[^-]+-([^-]+)-', inventory_path).group(1)
        elif 'agent' in inventory_path:
            os_name = re.search(r'/agent-[^-]+-([^-]+)-', inventory_path).group(1)
        elif 'central_components' in inventory_path:
            os_name = re.search(r'/central_components-[^-]+-([^-]+)-', inventory_path).group(1)

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
        if 'manager' in inventory_path:
            match = re.search(r'/manager-[^-]+-([^-]+)-', inventory_path)
        elif 'agent' in inventory_path:
            match = re.search(r'/agent-[^-]+-([^-]+)-', inventory_path)
        elif 'central_components' in inventory_path:
            match = re.search(r'/central_components-[^-]+-([^-]+)-', inventory_path)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def get_os_name_and_version_from_inventory(inventory_path) -> tuple:
        """
        It returns the linux os_name and version host inventory

        Args:
            inventory_path: host's inventory path

        Returns:
            tuple: linux os name and version (e.g., ('ubuntu', '22.04'))
        """
        if 'manager' in inventory_path:
            match = re.search(r'/manager-[^-]+-([^-]+)-([^-]+)-', inventory_path)
        elif 'agent' in inventory_path:
            match = re.search(r'/agent-[^-]+-([^-]+)-([^-]+)-', inventory_path)
        elif 'central_components' in inventory_path:
            match = re.search(r'/central_components-[^-]+-([^-]+)-([^-]+)-', inventory_path)
        if match:
            os_name = match.group(1)
            version = match.group(2)
            return os_name+'-'+version
        else:
            return None

    @staticmethod
    def get_os_version_from_inventory(inventory_path) -> str:
        """
        It returns the os version from the inventory information

        Args:
            inventory_path: host's inventory path

        Returns:
            str: os version
        """
        if 'manager' in inventory_path:
            match = re.search(r".*?/manager-.*?-.*?-(.*?)-.*?/inventory.yaml", inventory_path)
        elif 'agent' in inventory_path:
            match = re.search(r".*?/agent-.*?-.*?-(.*?)-.*?/inventory.yaml", inventory_path)
        elif 'central_components' in inventory_path:
            match = re.search(r".*?/central_components-.*?-.*?-(.*?)-.*?/inventory.yaml", inventory_path)
        if match:
            return match.group(1)
        else:
            return None


    @staticmethod
    def get_current_dir(inventory_path) -> str:
        """
        It returns the current directory

        Args:
            inventory_path: host's inventory path

        Returns:
            str: current directory
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            result = ConnectionManager.execute_commands(inventory_path, 'pwd')
            return result.get('output').replace("\n","")
        elif os_type == 'windows':
            return ConnectionManager.execute_commands(inventory_path, '(Get-Location).Path').get('output')
        elif os_type == 'macos':
            result = ConnectionManager.execute_commands(inventory_path, 'pwd').get('output')
            return result.replace("\n","")

    @staticmethod
    def get_internal_ip_from_aws_dns(dns_name) -> str:
        """
        It returns the private AWS IP from dns_name

        Args:
            dns_name (str): host's dns public dns name

        Returns:
            str: private ip
        """
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances(Filters=[{'Name': 'dns-name', 'Values': [dns_name]}])
        if response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            return instance['PrivateIpAddress']
        else:
            return None

    @staticmethod
    def get_public_ip_from_aws_dns(dns_name) -> str:
        """
        It returns the public AWS IP from dns_name

        Args:
            dns_name (str): host's dns public dns name

        Returns:
            str: public ip
        """
        try:
            ip_address = socket.gethostbyname(dns_name)
            return ip_address
        except socket.gaierror as e:
            logger.error("Error obtaining IP address:", e)
            return None

    @staticmethod
    def get_client_keys(inventory_path) -> list[dict]:
        """
        Get the client keys from the client.keys file in the host.

        Args:
            inventory_path (str): host's inventory path

        Returns:
            list: List of dictionaries with the client keys.
        """
        clients = []

        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            client_key = ConnectionManager.execute_commands(inventory_path, f'cat {CLIENT_KEYS}').get('output')
        elif os_type == 'windows':
            client_key = ConnectionManager.execute_commands(inventory_path, f'Get-Content "{WINDOWS_CLIENT_KEYS}"').get('output')
        elif os_type == 'macos':
            client_key = ConnectionManager.execute_commands(inventory_path, f'cat {MACOS_CLIENT_KEYS}').get('output')

        if client_key != None:
            lines = client_key.split('\n')[:-1]
            for line in lines:
                _id, name, address, password = line.strip().split()
                client_info = {
                    "id": _id,
                    "name": name,
                    "address": address,
                    "password": password
                }
                clients.append(client_info)
            return clients
        else:
            return []

    @staticmethod
    def has_curl(inventory_path) -> bool:
        """
        Returns yes in case that curl is installed in Linux/macOS.
        Args:
            inventory_path (str): host's inventory path
        Returns:
            bool: True/False.
        """
        return 'curl' in ConnectionManager.execute_commands(inventory_path, 'which curl').get('output')

class HostConfiguration:

    @staticmethod
    def sshd_config(inventory_path) -> None:
        """
        Configures sshd_config file to connect using password

        Args:
            inventory_path: host's inventory path

        """

        commands = ["sudo sed -i '/^PasswordAuthentication/s/^/#/' /etc/ssh/sshd_config", "sudo sed -i '/^PermitRootLogin no/s/^/#/' /etc/ssh/sshd_config", 'echo -e "PasswordAuthentication yes\nPermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config', 'sudo systemctl restart sshd', 'cat /etc/ssh/sshd_config']
        ConnectionManager.execute_commands(inventory_path, commands)


    @staticmethod
    def disable_firewall(inventory_path) -> None:
        """
        Disables firewall

        Args:
            inventory_path: host's inventory path

        """
        commands = []

        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            commands = ["sudo systemctl stop firewalld", "sudo systemctl disable firewalld"]
            if GeneralComponentActions.is_component_active(inventory_path, 'firewalld'):
                ConnectionManager.execute_commands(inventory_path, commands)

                logger.info(f'Firewall disabled on {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
            else:
                logger.info(f'No Firewall to disable on {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        elif os_type == 'windows':
            logger.info(f'Firewall disabled on {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
            commands = ["Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"]
            ConnectionManager.execute_commands(inventory_path, commands)
        elif os_type == 'macos':
            logger.info(f'Firewall disabled on {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
            ConnectionManager.execute_commands(inventory_path, 'sudo pfctl -d')

    def _extract_hosts(paths, is_aws):
        from .utils import Utils
        if is_aws:
            return [HostInformation.get_internal_ip_from_aws_dns(Utils.extract_ansible_host(path)) for path in paths]
        else:
            return [Utils.extract_ansible_host(path) for path in paths]

    @staticmethod
    def certs_create(wazuh_version, master_path, dashboard_path, indexer_paths=[], worker_paths=[], live="") -> None:
        """
        Creates wazuh certificates

        Args:
            wazuh_version (str): wazuh version
            master_path (str): wazuh master inventory_path
            dashboard_path (str): wazuh dashboard inventory_path
            indexer_paths (list): wazuh indexers list
            workers_paths (list): wazuh worker paths list

        """
        from .utils import Utils

        current_directory = HostInformation.get_current_dir(master_path)

        wazuh_version = '.'.join(wazuh_version.split('.')[:2])

        is_aws = 'amazonaws' in Utils.extract_ansible_host(master_path)

        master = HostConfiguration._extract_hosts([master_path], is_aws)[0]
        dashboard = HostConfiguration._extract_hosts([dashboard_path], is_aws)[0]
        indexers = HostConfiguration._extract_hosts(indexer_paths, is_aws)
        workers = HostConfiguration._extract_hosts(worker_paths, is_aws)

        ##Basic commands to setup the config file, add the ip for the master & dashboard
        os_name = HostInformation.get_os_name_from_inventory(master_path)

        if live == "False":
            s3_url = 'packages-dev.wazuh.com'
        else:
            s3_url = 'packages.wazuh.com'

        if os_name == 'debian':
            commands = [
                f'wget https://{s3_url}/{wazuh_version}/wazuh-install.sh',
                f'wget https://{s3_url}/{wazuh_version}/config.yml',
                f"sed -i '/^\s*#/d' {current_directory}/config.yml"
            ]
        else:
            commands = [
                f'curl -sO https://{s3_url}/{wazuh_version}/wazuh-install.sh',
                f'curl -sO https://{s3_url}/{wazuh_version}/config.yml',
                f"sed -i '/^\s*#/d' {current_directory}/config.yml"
            ]

        # Add master tag if there are workers
        if len(worker_paths) != 0:
            commands.append(f"""sed -i '/ip: "<wazuh-manager-ip>"/a\      node_type: master' {current_directory}/config.yml""")

        # Add manager and dashboard IP
        commands.extend([
            f"sed -i '0,/<wazuh-manager-ip>/s//{master}/' {current_directory}/config.yml",
            f"sed -i '0,/<dashboard-node-ip>/s//{dashboard}/' {current_directory}/config.yml"
        ])

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

        ConnectionManager.execute_commands(master_path, commands)

        current_from_directory = HostInformation.get_current_dir(master_path)

        assert HostInformation.file_exists(master_path, f'{current_from_directory}/wazuh-install-files.tar'), logger.error('wazuh-install-files.tar not created, check config.yml information')

    @staticmethod
    def scp_to(from_inventory_path, to_inventory_path, file_name) -> None:
        """
        Send via SCP from one host to another host

        Args:
            from_inventory_path (str): host that owns the file to be sent path
            to_inventory_path (str): host that recieves the file path
            file_name (str): file name that will be send to home/{user}

        """
        current_from_directory = HostInformation.get_current_dir(from_inventory_path)
        current_to_directory = HostInformation.get_current_dir(to_inventory_path)
        with open(from_inventory_path, 'r') as yaml_file:
            from_inventory_data = yaml.safe_load(yaml_file)

        with open(to_inventory_path, 'r') as yaml_file:
            to_inventory_data = yaml.safe_load(yaml_file)

        # Defining variables
        from_host = socket.gethostbyname(from_inventory_data.get('ansible_host'))
        from_key = from_inventory_data.get('ansible_ssh_private_key_file')
        from_user = from_inventory_data.get('ansible_user')
        from_port = from_inventory_data.get('ansible_port')

        to_host = socket.gethostbyname(to_inventory_data.get('ansible_host'))
        to_key = to_inventory_data.get('ansible_ssh_private_key_file')
        to_user = to_inventory_data.get('ansible_user')
        to_port = to_inventory_data.get('ansible_port')

        # Allowing handling permissions
        if file_name == 'wazuh-install-files.tar':
            ConnectionManager.execute_commands(from_inventory_path, f'chmod +rw {file_name}')
            logger.info('File permissions modified to be handled')

        # SCP
        if HostInformation.file_exists(from_inventory_path, f'{current_from_directory}/{file_name}'):
            subprocess.run(f'scp -i {from_key} -o StrictHostKeyChecking=no -P {from_port} {from_user}@{from_host}:{current_from_directory}/{file_name} {Path(__file__).parent}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logger.info(f'File copied from {HostInformation.get_os_name_and_version_from_inventory(from_inventory_path)} ({from_host}) to {Path(__file__).parent}/{file_name}')
        else:
            logger.error(f'File is not present in {HostInformation.get_os_name_and_version_from_inventory(from_inventory_path)} ({from_host}) in {current_from_directory}/{file_name}')
        if os.path.exists(f'{Path(__file__).parent}/wazuh-install-files.tar'):
            subprocess.run(f'scp -i {to_key} -o StrictHostKeyChecking=no -P {to_port} {Path(__file__).parent}/{file_name} {to_user}@{to_host}:{current_to_directory}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logger.info(f'Sending file from {current_from_directory}/{file_name} to {HostInformation.get_os_name_and_version_from_inventory(to_inventory_path)} ({to_host})')
        else:
            logger.error(f'Failure sending the file from {current_from_directory}/{file_name} to {HostInformation.get_os_name_and_version_from_inventory(to_inventory_path)} ({to_host})')

        # Restoring permissions
        if file_name == 'wazuh-install-files.tar':
            ConnectionManager.execute_commands(from_inventory_path, f'chmod 600 {file_name}')
            ConnectionManager.execute_commands(to_inventory_path, f'chmod 600 {file_name}')
            logger.info('File permissions were restablished')

        # Deleting file from localhost
        file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), file_name)

        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"The file {file_name} deleted in {Path(__file__).parent}")
        else:
            logger.error(f"The file {file_name} does not exist")

        assert HostInformation.file_exists(to_inventory_path, f'{current_to_directory}/{file_name}'), logger.error(f'Failure sending the file: {file_name} to {HostInformation.get_os_name_and_version_from_inventory(to_inventory_path)}')
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
    def _checkfiles(inventory_path, os_type, directory, filters_keywords= None, hash_algorithm='sha256') -> dict:
        """
        It captures a structure of a directory
        Returns:
            Dict: dict of directories:hash
        """
        if 'linux' == os_type:
            filters = f"| grep -v {filters_keywords[0]}"
            for filter_ in filters_keywords[1:]:
                filters += f" | grep -v {filter_}"
            command = f'sudo find {directory} -type f -exec sha256sum {{}} + {filters}'
            result = ConnectionManager.execute_commands(inventory_path, command).get('output')

        elif 'macos' == os_type:
            filters = f"| grep -v {filters_keywords[0]}"
            for filter_ in filters_keywords[1:]:
                filters += f" | grep -v {filter_}"
            command = f'sudo find {directory} -type f -exec shasum -a 256 {{}} \; {filter}'
            result = ConnectionManager.execute_commands(inventory_path, command).get('output')

        elif 'windows' in os_type:
            quoted_filters = ['"{}"'.format(keyword) for keyword in filters_keywords]
            filter_files = ",".join(quoted_filters)
            command = f"$includedDirectories = @('{directory}') "
            command += f"\n$excludedPatterns = @({filter_files})"
            command += """
                try {
                    foreach ($dir in $includedDirectories) {
                        Get-ChildItem -Path "$dir" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                            $fileName = $_.FullName
                            $hash = Get-FileHash -Path $fileName -Algorithm SHA256 -ErrorAction SilentlyContinue
                            if ($hash) {
                                $exclude = $false
                                foreach ($pattern in $excludedPatterns) {
                                    if ($fileName -like "*$pattern*") {
                                        $exclude = $true
                                        break
                                    }
                                }
                                if (-not $exclude) {
                                    Write-Output "$($hash.Hash) $fileName"
                                }
                            }
                        }
                    }
                } catch {
                    Write-Host "Error: $_"
                }

            """

            result = ConnectionManager.execute_commands(inventory_path, command).get('output')
        else:
            logger.info(f'Unsupported operating system')
            return None
        snapshot = {}
        for line in result.splitlines():
            hash_value, file_path = line.split(maxsplit=1)
            snapshot[file_path] = hash_value

        return snapshot


    @staticmethod
    def _perform_scan(inventory_path, os_type, directories, filters_keywords):
        logger.info(f'Generating Snapshot for Checkfile in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        return {directory: CheckFiles._checkfiles(inventory_path, os_type, directory, filters_keywords) for directory in directories}


    @staticmethod
    def _calculate_changes(initial_scan, second_scan):
        added_files = list(set(second_scan) - set(initial_scan))
        removed_files = list(set(initial_scan) - set(second_scan))
        modified_files = [path for path in set(initial_scan) & set(second_scan) if initial_scan[path] != second_scan[path]]

        return {'added': added_files, 'removed': removed_files, 'modified': modified_files}


    @staticmethod
    def perform_action_and_scan(inventory_path, callback) -> dict:
        """
        Performs an action (callback) and scans pre and post action

        Args:
            inventory_path: host's inventory path
            callback (callback): callback


        Returns:
            returns a dictionary that contains the changes between the pre and the post scan
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            directories = ['/boot', '/usr/bin', '/root', '/usr/sbin']
            filters_keywords = ['grep', 'tar', 'coreutils', 'sed', 'procps', 'gawk', 'lsof', 'curl', 'openssl', 'libcap', 'apt-transport-https', 'libcap2-bin', 'software-properties-common', 'gnupg', 'gpg']
        elif os_type == 'windows':
            directories = ['C:\\Program Files', 'C:\\Program Files (x86)','C:\\Users\\vagrant']
            filters_keywords = ['log','tmp','ossec-agent', 'EdgeUpdate']
        elif os_type == 'macos':
            directories = ['/usr/bin', '/usr/sbin']
            filters_keywords = ['grep']

        initial_scans = CheckFiles._perform_scan(inventory_path, os_type, directories, filters_keywords)
        callback()
        second_scans = CheckFiles._perform_scan(inventory_path, os_type, directories, filters_keywords)
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
        logger.info(f'Getting status of {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            return ConnectionManager.execute_commands(inventory_path, f'systemctl status {host_role}').get('output')
        elif os_type == 'windows':
            result = ConnectionManager.execute_commands(inventory_path, "Get-Service -Name 'Wazuh' | Format-Table -HideTableHeaders Status")
            if result.get('success'):
                return result.get('output')
        elif os_type == 'macos':
            return ConnectionManager.execute_commands(inventory_path, f'{MACOS_WAZUH_CONTROL} status | grep {host_role}').get('output')

    @staticmethod
    def component_stop(inventory_path, host_role) -> None:
        """
        Stops the component

        Args:
            inventory_path: host's inventory path
            host_role: role of the component
        """
        logger.info(f'Stopping {host_role} in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            ConnectionManager.execute_commands(inventory_path, f'systemctl stop {host_role}')
        elif os_type == 'windows':
            ConnectionManager.execute_commands(inventory_path, f'NET STOP Wazuh')
        elif os_type == 'macos':
            ConnectionManager.execute_commands(inventory_path, f'{MACOS_WAZUH_CONTROL} stop | grep {host_role}')

    @staticmethod
    def component_restart(inventory_path, host_role) -> None:
        """
        Restarts the component

        Args:
            inventory_path: host's inventory path
            host_role: role of the component
        """

        logger.info(f'Restarting {host_role} in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            ConnectionManager.execute_commands(inventory_path, f'systemctl restart {host_role}')
        elif os_type == 'windows':
            ConnectionManager.execute_commands(inventory_path, 'NET STOP Wazuh')
            ConnectionManager.execute_commands(inventory_path, 'NET START Wazuh')
        elif os_type == 'macos':
            ConnectionManager.execute_commands(inventory_path, f'{MACOS_WAZUH_CONTROL} restart | grep {host_role}')

    @staticmethod
    def component_start(inventory_path, host_role) -> None:
        """
        Starts the component

        Args:
            inventory_path: host's inventory path
            host_role: role of the component
        """

        logger.info(f'Starting {host_role} in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')

        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            ConnectionManager.execute_commands(inventory_path, f'systemctl start {host_role}')
        elif os_type == 'windows':
            ConnectionManager.execute_commands(inventory_path, 'NET START Wazuh')
        elif os_type == 'macos':
            ConnectionManager.execute_commands(inventory_path, f'{MACOS_WAZUH_CONTROL} start | grep {host_role}')

    @staticmethod
    def get_component_version(inventory_path) -> str:
        """
        Returns the installed component version

        Args:
            inventory_path: host's inventory path

        Returns:
            str: version
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            return ConnectionManager.execute_commands(inventory_path, f'{WAZUH_CONTROL} info -v').get('output')

        elif os_type == 'windows':
            return ConnectionManager.execute_commands(inventory_path, f'Get-Content "{WINDOWS_VERSION}"').get('output')#.replace("\n", ""))

        elif os_type == 'macos':
            return ConnectionManager.execute_commands(inventory_path, f'{MACOS_WAZUH_CONTROL} info -v').get('output')

    @staticmethod
    def get_component_revision(inventory_path) -> str:
        """
        Returns the Agent revision number

        Args:
            inventory_path: host's inventory path

        Returns:
            str: revision number
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            return ConnectionManager.execute_commands(inventory_path, f'{WAZUH_CONTROL} info -r').get('output')
        elif os_type == 'windows':
            return ConnectionManager.execute_commands(inventory_path, f'Get-Content "{WINDOWS_REVISION}"').get('output')
        elif os_type == 'macos':
            return ConnectionManager.execute_commands(inventory_path, f'{MACOS_WAZUH_CONTROL} info -r').get('output')

    @staticmethod
    def has_agent_client_keys(inventory_path) -> bool:
        """
        Returns the True of False depending if in the component Client.keys exists

        Args:
            inventory_path: host's inventory path

        Returns:
            bool: True/False
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            result = ConnectionManager.execute_commands(inventory_path, f'[ -f {CLIENT_KEYS} ] && echo true || echo false')
            return 'true' in result.get('output')
        elif os_type == 'windows':
            result = ConnectionManager.execute_commands(inventory_path, f'Test-Path -Path "{WINDOWS_CLIENT_KEYS}"')
            if result.get('success'):
                return result.get('output', '')
            return False
        elif os_type == 'macos':
            return HostInformation.file_exists(inventory_path, f'{MACOS_CLIENT_KEYS}')

    @staticmethod
    def is_component_active(inventory_path, host_role) -> bool:
        """
        Returns the True of False depending if the component is Active

        Args:
            inventory_path: host's inventory path
            host_role: role of the component

        Returns:
            bool: True/False
        """
        os_type = HostInformation.get_os_type(inventory_path)

        if os_type == 'linux':
            return 'active' == ConnectionManager.execute_commands(inventory_path, f'systemctl is-active {host_role}').get('output').replace("\n", "")

        elif os_type == 'windows':
            result = ConnectionManager.execute_commands(inventory_path, "Get-Service -Name 'Wazuh'")
            return result.get('success')

        elif os_type == 'macos':
            result = ConnectionManager.execute_commands(inventory_path, f'ps aux | grep {host_role} | grep -v grep')
            if result.get('output') == None:
                return False
            else:
                return result.get('success')


class Waits:

    @staticmethod
    def dynamic_wait(expected_condition_func, cycles=10, waiting_time=10) -> None:
        """
        Waits the process during assigned cycles for the assigned seconds

        Args:
            expected_condition_func (lambda function): The function that returns True when the expected condition is met
            cycles(int): Number of cycles
            waiting_Time(int): Number of seconds per cycle

        """
        for _ in range(cycles):
            if expected_condition_func():
                break
            else:
                time.sleep(waiting_time)
        else:
            logger.error('Time out, Expected condition was not met')
            raise RuntimeError(f'Time out')
