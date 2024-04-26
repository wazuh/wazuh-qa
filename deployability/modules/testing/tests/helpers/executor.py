# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import requests
import subprocess
import urllib3
import yaml
import winrm

from base64 import b64encode

class ConectionInventory():
    host: str
    port: int
    password: str | None = None
    username: str
    private_key_path: str | None = None

    @staticmethod
    def _get_inventory_data(inventory_path) -> dict:
        with open(inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        return {
            'host': inventory_data.get('ansible_host'),
            'port': inventory_data.get('ansible_port'),
            'password': inventory_data.get('ansible_password', None),
            'username': inventory_data.get('ansible_user'),
            'private_key_path': inventory_data.get('ansible_ssh_private_key_file', None)
        }

class ConnectionManager:
    @staticmethod
    def _get_executor(inventory_path) -> type:
        from .generic import HostInformation

        os_type = HostInformation.get_os_type(inventory_path)
        if os_type == "windows":
            return WindowsExecutor
        else:
            return UnixExecutor

    @staticmethod
    def execute_commands(inventory_path, commands) -> dict:
        executor = ConnectionManager._get_executor(inventory_path)
        if isinstance(commands, str):
            try:
                result = executor._execute_command(ConectionInventory._get_inventory_data(inventory_path), commands)
            except Exception as e:
                raise Exception(f'Error executing command: {commands} with error: {e}')
            return result
        else:
            results = {}
            for command in commands:
                result = executor._execute_command(ConectionInventory._get_inventory_data(inventory_path), command)
                results[command] = result
            return results

class WindowsExecutor():
    @staticmethod
    def _execute_command(data: ConectionInventory, command) -> dict:
        if data.get('port') == 5986:
            protocol = 'https'
        else:
            protocol = 'http'

        endpoint_url = f"{protocol}://{data.get('host')}:{data.get('port')}"

        try:
            session = winrm.Session(endpoint_url, auth=(data.get('username'), data.get('password')),transport='ntlm', server_cert_validation='ignore')
            ret = session.run_ps(command)

            if ret.status_code == 0:
                return {'success': True, 'output': ret.std_out.decode('utf-8').strip()}
            else:
                return {'success': False, 'output': ret.std_err.decode('utf-8').strip()}
        except Exception as e:
            raise Exception(f'Error executing command: {command} with error: {e}')

class UnixExecutor():
    @staticmethod
    def _execute_command(data, command) -> dict:

        ssh_command = [
            "ssh",
            "-i", data.get('private_key_path'),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(data.get('port')),
            f"{data.get('username')}@{data.get('host')}",
            "sudo",
            command
        ]

        try:
            ret = subprocess.run(ssh_command, stdout=subprocess.PIPE, text=True)
            if ret.stdout:
                return {'success': True, 'output': ret.stdout.replace('\n', '')}
            if ret.stderr:
                return {'success': False, 'output': ret.stderr.replace('\n', '')}
            return {'success': False, 'output': None}

        except Exception as e:
            #return {'success': False, 'output': ret.stderr}
            raise Exception(f'Error executing command: {command} with error: {e}')

# ------------------------------------------------------


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
        result = ConnectionManager.execute_commands(self.inventory_path, 'pwd')
        file_path = result.get('output') + '/wazuh-install-files/wazuh-passwords.txt'
        result = ConnectionManager.execute_commands(self.inventory_path, f'test -f {file_path} && echo "true" || echo "false"')
        if not 'true' in result.get('output'):
            ConnectionManager.execute_commands(self.inventory_path, 'tar -xvf wazuh-install-files.tar')
        result = ConnectionManager.execute_commands(self.inventory_path, "grep api_password wazuh-install-files/wazuh-passwords.txt | head -n 1 | awk '{print $NF}'")
        password = result.get('output')[1:-1]
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
