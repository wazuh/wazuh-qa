# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import time

from .executor import ConnectionManager, WazuhAPI
from modules.testing.utils import logger

class WazuhIndexer:

    @staticmethod
    def get_indexer_version(inventory_path) -> str:
        """
        Returns the Wazuh indexer version

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - str: Version of the Wazuh indexer.
        """

        return ConnectionManager.execute_commands(inventory_path,'cat /usr/share/wazuh-indexer/VERSION').get('output').strip()


    @staticmethod
    def are_indexer_internal_users_complete(inventory_path) -> bool:
        """
        Returns True/False depending on the existance of all the expected internal users

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: True/False depending on the status.
        """

        users_to_check = [
            'admin',
            'kibanaserver',
            'kibanaro',
            'logstash',
            'readall',
            'snapshotrestore'
        ]
        report_of_users = ConnectionManager.execute_commands(inventory_path, "cat /etc/wazuh-indexer/opensearch-security/internal_users.yml | grep '^[a-z]'").get('output')
        for user in users_to_check:
            if user not in report_of_users:
                return False
        return True


    @staticmethod
    def are_indexes_working(wazuh_api: WazuhAPI, inventory_path) -> bool:
        """
        Returns True/False depending on the working status of the Wazuh indexes

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: True/False depending on the status.
        """
        indexes = ConnectionManager.execute_commands(inventory_path, f"curl -k -u {wazuh_api.username}:{wazuh_api.password} {wazuh_api.api_url}/_cat/indices/?pretty").get('output').strip().split('\n')
        for index in indexes:
            if 'red' not in index:
                return True
        return False


    @staticmethod
    def is_index_cluster_working(wazuh_api: WazuhAPI, inventory_path) -> bool:
        """
        Returns True/False depending on the status of the Wazuh indexer cluster

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: True/False depending on the status.
        """
        response = ConnectionManager.execute_commands(inventory_path, f"curl -k -u {wazuh_api.username}:{wazuh_api.password} {wazuh_api.api_url}/_cat/health").get('output')
        return 'green' in response


    @staticmethod
    def is_indexer_port_open(inventory_path, wait=10, cycles=50) -> bool:
        """
        Check if the Wazuh indexer port is open

        Args:
            inventory_path (str): Wazuh indexer inventory.

        Returns:
            str: OS name.
        """
        time.sleep(5)
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = ConnectionManager.execute_commands(inventory_path, 'ss -t -a -n | grep ":9200"').get('output') or ""
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
