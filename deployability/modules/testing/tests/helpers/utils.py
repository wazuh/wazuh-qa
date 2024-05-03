# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import paramiko
import re
import yaml
import logging
import time
import winrm

from modules.testing.utils import logger

paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(logging.CRITICAL)


class Utils:

    @staticmethod
    def extract_ansible_host(file_path) -> str:
        with open(file_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)
        return inventory_data.get('ansible_host')

    @staticmethod
    def check_inventory_connection(inventory_path, attempts=10, sleep=30) -> bool:
        if 'manager' in inventory_path:
            match = re.search(r'/manager-[^-]+-([^-]+)-([^-]+)-', inventory_path)
        elif 'agent' in inventory_path:
            match = re.search(r'/agent-[^-]+-([^-]+)-([^-]+)-', inventory_path)
        elif 'central_components' in inventory_path:
            match = re.search(r'/central_components-[^-]+-([^-]+)-([^-]+)-', inventory_path)
        if match:
            os_name = match.group(1)+ '-' + match.group(2)
        logger.info(f'Checking connection to {os_name}')
        try:
            with open(inventory_path, 'r') as file:
                inventory_data = yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(logger.error(f'File not found in {os_name}'))
        except yaml.YAMLError:
            raise ValueError(logger.error(f'Invalid inventory information in {os_name}'))

        host = inventory_data.get('ansible_host')
        port = inventory_data.get('ansible_port')
        private_key_path = inventory_data.get('ansible_ssh_private_key_file', None)
        username = inventory_data.get('ansible_user')
        password = inventory_data.get('ansible_password', None)

        try:
            with open(inventory_path.replace('inventory', 'track'), 'r') as file:
                data = yaml.safe_load(file)
            if 'platform' in data:
                os_type = data['platform']
            else:
                raise KeyError("The 'platform' key was not found in the YAML file.")
        except FileNotFoundError:
            logger.error(f"The YAML file '{inventory_path}' was not found.")
        except yaml.YAMLError as e:
            logger.error(f"Error while loading the YAML file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")

        if private_key_path != None:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

            for attempt in range(1, attempts + 1):
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
                try:
                    ssh.connect(hostname=host, port=port, username=username, pkey=private_key)
                    logger.info(f'Connection established successfully in {os_name}')
                    ssh.close()
                    return True
                except paramiko.AuthenticationException:
                    logger.error(f'Authentication error. Check SSH credentials in {os_name}')
                    return False
                except Exception as e:
                    logger.warning(f'Error on attempt {attempt} of {attempts}: {e}')
                time.sleep(sleep)

        else:
            if os_type == 'windows':
                if port == 5986:
                    protocol = 'https'
                else:
                    protocol = 'http'
                endpoint_url = f'{protocol}://{host}:{port}'

                for attempt in range(1, attempts + 1):
                    try:
                        session = winrm.Session(endpoint_url, auth=(username, password),transport='ntlm', server_cert_validation='ignore')
                        cmd = session.run_cmd('ipconfig')
                        if cmd.status_code == 0:
                            logger.info("WinRM connection successful.")
                            return True
                        else:
                            logger.error('WinRM connection failed. Check the credentials in the inventory file.')
                            return False
                    except Exception as e:
                        logger.warning(f'Error on attempt {attempt} of {attempts}: {e}')
                    time.sleep(sleep)

            elif os_type == 'macos':
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                for attempt in range(1, attempts + 1):
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(hostname=host, port=port, username=username, password=password)
                        logger.info(f'Connection established successfully in {os_name}')
                        ssh.close()
                        return True
                    except paramiko.AuthenticationException:
                        logger.error(f'Authentication error. Check SSH credentials in {os_name}')
                        return False
                    except Exception as e:
                        logger.warning(f'Error on attempt {attempt} of {attempts}: {e}')
                    time.sleep(sleep)

        logger.error(f'Connection attempts failed after {attempts} tries. Connection timeout in {os_name}')
        return False
