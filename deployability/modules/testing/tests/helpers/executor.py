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

        return result.stdout

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
