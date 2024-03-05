import yaml
import subprocess


class Executor:
    def __init__(self):
        pass

    def execute_command(inventory_path, command):

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

    def execute_commands(inventory_path, commands=[]):

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
            print(results[command])

        return results
