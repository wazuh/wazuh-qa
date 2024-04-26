# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
import socket
import json
import time

from .constants import CLUSTER_CONTROL, AGENT_CONTROL, WAZUH_CONF, WAZUH_ROOT
from .executor import Executor, WazuhAPI
from .generic import HostInformation, CheckFiles
from modules.testing.utils import logger
from .utils import Utils


class WazuhDashboard:

    @staticmethod
    def get_dashboard_version(inventory_path) -> str:
        """
        Returns dashboard version

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - str: Version of the dashboard.
        """

        return Executor.execute_command(inventory_path,'cat /usr/share/wazuh-dashboard/VERSION').strip()


    @staticmethod
    def isDashboard_active(inventory_path) -> bool:
        """
        Returns True/False depending if the dashboard is active or not

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: Status of the dashboard.
        """

        return '200' in Executor.execute_command(inventory_path, 'curl -Is -k https://localhost/app/login?nextUrl=%2F | head -n 1')


    @staticmethod
    def isDashboardKeystore_working(inventory_path) -> bool:
        """
        Returns True/False depending if the dashboard keystore is active or not

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: Status of the dashboard keystore.
        """

        return 'No such file or directory' not in Executor.execute_command(inventory_path, '/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore list --allow-root')


    @staticmethod
    def areDashboardNodes_working(wazuh_api: WazuhAPI) -> str:
        """
        Returns True/False depending the status of Dashboard nodes

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
            logger.error(f'The dashboard API returned: {response.status_code}')

    @staticmethod
    def isDashboard_port_opened(inventory_path, wait=10, cycles=50):
        """
        Check if dashboard port is open

        Args:
            inventory_path (str): Dashboard inventory.

        Returns:
            str: Os name.
        """
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = Executor.execute_command(inventory_path, 'ss -t -a -n | grep ":443"').strip().split('\n')
            for port in ports:
                if 'ESTAB' in port or 'LISTEN' in port:
                    continue
                else:
                    time.sleep(wait)
                    wait_cycles += 1
                    break
            else:
                return True
        return False
