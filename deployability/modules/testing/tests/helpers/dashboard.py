# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
import json
import time

from .executor import ConnectionManager, WazuhAPI
from modules.testing.utils import logger


class WazuhDashboard:

    @staticmethod
    def get_dashboard_version(inventory_path) -> str:
        """
        Returns Wazuh dashboard version

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - str: Version of the Wazuh dashboard.
        """

        return ConnectionManager.execute_commands(inventory_path,'cat /usr/share/wazuh-dashboard/VERSION').get('output').strip()


    @staticmethod
    def is_dashboard_active(inventory_path) -> bool:
        """
        Returns True/False depending if the dashboard service is active or not

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: Status of the Wazuh dashboard service.
        """

        return '200' in ConnectionManager.execute_commands(inventory_path, 'curl -Is -k https://localhost/app/login?nextUrl=%2F | head -n 1').get('output')


    @staticmethod
    def is_dashboard_keystore_working(inventory_path) -> bool:
        """
        Returns True/False depending if the Wazuh dashboard keystore is active or not

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: Status of the Wazuh dashboard keystore.
        """

        return 'No such file or directory' not in ConnectionManager.execute_commands(inventory_path, '/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore list --allow-root').get('output')


    @staticmethod
    def are_dashboard_nodes_working(wazuh_api: WazuhAPI) -> str:
        """
        Returns True/False depending the status of Wazuh dashboard nodes

        Returns:
        - bool: True/False depending on the status.
        """
        response = requests.get(f"{wazuh_api.api_url}/api/status", auth=(wazuh_api.username, wazuh_api.password), verify=False)

        result = True
        if response.status_code == 200:
            for status in json.loads((response.text))['status']['statuses']:
                if status['state'] ==  'green' or status['state'] ==  'yellow':
                    result = True
                else: 
                    result = False
            return result

        else:
            logger.error(f'The Wazuh dashboard API returned: {response.status_code}')

    @staticmethod
    def is_dashboard_port_open(inventory_path, wait=10, cycles=50):
        """
        Check if the Wazuh dashboard port is open

        Args:
            inventory_path (str): Wazuh dashboard inventory.

        Returns:
            str: OS name.
        """
        time.sleep(5)
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = ConnectionManager.execute_commands(inventory_path, 'ss -t -a -n | grep ":443"').get('output') or ""
            ports = ports.strip().split('\n')
            for port in ports:
                if any(state in port for state in ['ESTAB', 'LISTEN']):
                    continue
                else:
                    time.sleep(wait)
                    wait_cycles += 1
                    break
            else:
                return True
        return False
