# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
import socket

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
        """

        return Executor.execute_command(inventory_path,'cat /usr/share/wazuh-dashboard/VERSION')


    @staticmethod
    def isDashboard_active(inventory_path) -> bool:
        """
        Returns True/False depending if the dashboard is active or not

        Args:
            inventory_path (str): host's inventory path
        """

        return '200' in Executor.execute_command(inventory_path, 'curl -Is -k https://localhost/app/login?nextUrl=%2F | head -n 1')


    @staticmethod
    def isDashboardKeystore_working(inventory_path) -> bool:
        """
        Returns True/False depending if the dashboard keystore is active or not

        Args:
            inventory_path (str): host's inventory path
        """

        return 'No such file or directory' not in Executor.execute_command(inventory_path, '/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore list --allow-root')


    @staticmethod
    def areIndexes_working(wazuh_api: WazuhAPI) -> str:
        """
        Function to get the status of an agent given its name.
        
        Args:
        - agents_data (list): List of dictioconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaanaries conaaaaa.
        - agent_name (str): Name of the agent whoseconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaa status is to be obtained.
        
        Returns:
        - str: Status of the agent if found in the daconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaconaaaaaa, otherwise returns None.
        """
        logger.error(wazuh_api.api_url)
        logger.error(wazuh_api.password)
        logger.error(wazuh_api.username)
        response = requests.get(f"{wazuh_api.api_url}/_cat/indices/?pretty", auth=(wazuh_api.username, wazuh_api.password), verify=False)


        return response