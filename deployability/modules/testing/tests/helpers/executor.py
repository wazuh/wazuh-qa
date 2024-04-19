# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import requests
import subprocess
import urllib3
import yaml
import winrm
from .generic import HostInformation

from base64 import b64encode


class Executor:

    @staticmethod
    def execute_command(inventory_path, command) -> str:

        with open(inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        host = inventory_data.get('ansible_host')
        port = inventory_data.get('ansible_port')
        private_key_path = inventory_data.get('ansible_ssh_private_key_file')
        username = inventory_data.get('ansible_user')

        ssh_command = [
            "ssh",
            "-i", private_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(port),
            f"{username}@{host}",
            "sudo",
            command
        ]
        result = subprocess.run(ssh_command, stdout=subprocess.PIPE, text=True)

        return result.stdout

    @staticmethod
    def execute_windows_command(inventory_path, command) -> str:

        with open(inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        windows_host = inventory_data.get('ansible_host')
        windows_port = inventory_data.get('ansible_port')
        windows_password = inventory_data.get('ansible_password')
        windows_username = inventory_data.get('ansible_user')

        if windows_port == 5986:
            windows_protocol = 'https'
        else:
            windows_protocol = 'http'

        endpoint_url = f'{windows_protocol}://{windows_host}:{windows_port}'

        try:
            session = winrm.Session(endpoint_url, auth=(windows_username, windows_password),transport='ntlm', server_cert_validation='ignore')
            ret = session.run_cmd(command)
            if ret.status_code == 0:
                return ret.std_out
            else:
                return Exception(f'Error executing command: {command}')
        except Exception as e:
            raise Exception(f'Error executing command: {command}')


    @staticmethod
    def execute_commands(inventory_path, commands) -> dict:

        results = {}
        os_type = HostInformation.get_os_type(inventory_path)

        if isinstance(commands, str):
            commands = [commands]

        for command in commands:
            if os_type == "windows":
                results[command] = Executor.execute_windows_command(inventory_path, command)
            else:
                results[command] = Executor.execute_command(inventory_path, command)

        return results


class WazuhAPI:
    def __init__(self, inventory_path):
        self.inventory_path = inventory_path
        self.api_url = None
        self.headers = None
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._authenticate()

    def _authenticate(self):
        with open(self.inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        user = 'wazuh'

        #----Patch issue https://github.com/wazuh/wazuh-packages/issues/2883-------------
        file_path = Executor.execute_commands(self.inventory_path, 'pwd').replace("\n","") + '/wazuh-install-files/wazuh-passwords.txt'
        if not 'true' in Executor.execute_commands(self.inventory_path, f'test -f {file_path} && echo "true" || echo "false"'):
            Executor.execute_commands(self.inventory_path, 'tar -xvf wazuh-install-files.tar')
        password = Executor.execute_commands(self.inventory_path, "grep api_password wazuh-install-files/wazuh-passwords.txt | head -n 1 | awk '{print $NF}'").replace("'","").replace("\n","")
        #--------------------------------------------------------------------------------

        login_endpoint = 'security/user/authenticate'
        host = inventory_data.get('ansible_host')
        port = '55000'
        login_url = f"https://{host}:{port}/{login_endpoint}"
        basic_auth = f"{user}:{password}".encode()
        login_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

        token = json.loads(requests.post(login_url, headers=login_headers, verify=False).content.decode())['data']['token']

        self.api_url = f'https://{host}:{port}'
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        }
