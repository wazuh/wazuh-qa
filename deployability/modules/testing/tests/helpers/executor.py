# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import requests
import paramiko
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
        elif os_type == "linux":
            return UnixExecutor
        elif os_type == "macos":
            return MacosExecutor

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


class MacosExecutor():
    @staticmethod
    def _execute_command(data, command) -> dict:
        if data.get('private_key_path') == None:
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(hostname=data.get('host'), port=data.get('port'), username=data.get('username'), password=data.get('password'))
                stdin, stdout, stderr = ssh_client.exec_command(f"sudo {command}")

                stdout_str = ''.join(stdout.readlines())
                stderr_str = ''.join(stderr.readlines())

                ssh_client.close()

                if stdout_str:
                    return {'success': True, 'output': stdout_str.replace('\n', '')}
                if stderr_str:
                    return {'success': False, 'output': stderr_str.replace('\n', '')}
                return {'success': False, 'output': None}

            except Exception as e:
                raise Exception(f'Error executing command: {command} with error: {e}')
        else:
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
    def __init__(self, inventory_path, component=None):
        self.inventory_path = inventory_path
        self.api_url = None
        self.headers = None
        self.component = component
        self.username = None
        self.password = None
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._authenticate()

    def _extract_password(self, file_path, keyword):
        if not 'true' in ConnectionManager.execute_commands(self.inventory_path, f'test -f {file_path} && echo "true" || echo "false"').get('output'):
            ConnectionManager.execute_commands(self.inventory_path, 'tar -xvf wazuh-install-files.tar')
        return ConnectionManager.execute_commands(self.inventory_path, f"grep {keyword} {file_path} | head -n 1 | awk '{{print $NF}}'").get('output').replace("'", "").replace("\n", "")

    def _authenticate(self):
        with open(self.inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        user = 'wazuh'
        file_path = ConnectionManager.execute_commands(self.inventory_path, 'pwd').get('output').replace("\n", "") + '/wazuh-install-files/wazuh-passwords.txt'
        password = self._extract_password(file_path, 'api_password')

        login_endpoint = 'security/user/authenticate'
        host = inventory_data.get('ansible_host')
        port = '55000'
        login_url = f"https://{host}:{port}/{login_endpoint}"
        basic_auth = f"{user}:{password}".encode()
        login_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

        token = json.loads(requests.post(login_url, headers=login_headers, verify=False).content.decode())['data']['token']

        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        }

        self.api_url = f'https://{host}:{port}'

        if self.component == 'dashboard' or self.component == 'indexer':
            self.username = 'admin'
            password = self._extract_password(file_path, 'indexer_password')
            self.password = password
            self.api_url = f'https://{host}' if self.component == 'dashboard' else f'https://127.0.0.1:9200'
