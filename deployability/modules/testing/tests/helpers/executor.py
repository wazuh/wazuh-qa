import yaml
import subprocess
import requests
import urllib3
from base64 import b64encode
import json


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
            f"{username}@{host}",
            "sudo", 
            command
        ]
        result = subprocess.run(ssh_command, stdout=subprocess.PIPE, text=True)

        return result.stdout.replace("\n","")

    @staticmethod
    def execute_commands(inventory_path, commands=[]) -> dict:

        with open(inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        host = inventory_data.get('ansible_host')
        port = inventory_data.get('ansible_port')
        private_key_path = inventory_data.get('ansible_ssh_private_key_file')
        username = inventory_data.get('ansible_user')

        results = {}
        for command in commands:
            ssh_command = [
                "ssh",
                "-i", private_key_path,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                f"{username}@{host}",
                "sudo", 
                command
            ]

            results[command] = subprocess.run(ssh_command, stdout=subprocess.PIPE, text=True).stdout

        return results


class WazuhAPI:
    def __init__(self, inventory_path, wazuh_user='wazuh', wazuh_password='wazuh'):
        self.inventory_path = inventory_path
        self.api_url = None
        self.headers = None
        self.wazuh_user = wazuh_user
        self.wazuh_password = self._get_wazuh_api_password()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._authenticate()


    def _get_wazuh_api_password(self):
            #------------Patch issue https://github.com/wazuh/wazuh-packages/issues/2883---------------------
            file_path = Executor.execute_command(self.inventory_path, 'pwd').replace("\n","") + '/wazuh-install-files/wazuh-passwords.txt '
            if not 'true' in Executor.execute_command(self.inventory_path, f'test -f {file_path} && echo "true" || echo "false"'):
                Executor.execute_command(self.inventory_path, 'tar -xvf wazuh-install-files.tar')
            return Executor.execute_command(self.inventory_path, "grep api_password wazuh-install-files/wazuh-passwords.txt | head -n 1 | awk '{print $NF}'").replace("'","").replace("\n","")


    def _authenticate(self):
        with open(self.inventory_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)

        user = self.wazuh_user 
        password = self.wazuh_password
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

