# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import requests
import subprocess
import urllib3
import yaml

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
    def execute_commands(inventory_path, commands=[]) -> dict:

        results = {}
        for command in commands:
            results[command] = Executor.execute_command(inventory_path, command)

        return results


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
        if not 'true' in Executor.execute_command(self.inventory_path, f'test -f {file_path} && echo "true" || echo "false"'):
            Executor.execute_command(self.inventory_path, 'tar -xvf wazuh-install-files.tar')
        return Executor.execute_command(self.inventory_path, f"grep {keyword} {file_path} | head -n 1 | awk '{{print $NF}}'").replace("'", "").replace("\n", "")

    def _authenticate(self):
        with open(self.inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        user = 'wazuh'
        file_path = Executor.execute_command(self.inventory_path, 'pwd').replace("\n", "") + '/wazuh-install-files/wazuh-passwords.txt'
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