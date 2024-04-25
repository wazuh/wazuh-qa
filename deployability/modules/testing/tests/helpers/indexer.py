# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import time

from .executor import Executor, WazuhAPI
from modules.testing.utils import logger

class WazuhIndexer:

    @staticmethod
    def get_indexer_version(inventory_path) -> str:
        """
        Returns indexer version

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - str: Version of the indexer.
        """

        return Executor.execute_command(inventory_path,'cat /usr/share/wazuh-indexer/VERSION').strip()


    @staticmethod
    def areIndexer_internalUsers_complete(inventory_path) -> bool:
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
        report_of_users = Executor.execute_command(inventory_path, "cat /etc/wazuh-indexer/opensearch-security/internal_users.yml | grep '^[a-z]'")
        for user in users_to_check:
            if user not in report_of_users:

                return False

        return True


    @staticmethod
    def areIndexes_working(wazuh_api: WazuhAPI, inventory_path) -> bool:
        """
        Returns True/False depending on the working status of the indexes

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: True/False depending on the status.
        """
        indexes = Executor.execute_command(inventory_path, f"curl -k -u {wazuh_api.username}:{wazuh_api.password} {wazuh_api.api_url}/_cat/indices/?pretty").strip().split('\n')
        for index in indexes:
            if 'red' not in index:

                return True
        return False


    @staticmethod
    def isIndexCluster_working(wazuh_api: WazuhAPI, inventory_path) -> bool:
        """
        Returns True/False depending on the status of the indexer Cluster

        Args:
            inventory_path (str): host's inventory path

        Returns:
        - bool: True/False depending on the status.
        """
        response = Executor.execute_command(inventory_path, f"curl -k -u {wazuh_api.username}:{wazuh_api.password} {wazuh_api.api_url}/_cat/health")
        return 'green' in response


    @staticmethod
    def isIndexer_port_opened(inventory_path, wait=0, cycles=10):
        """
        Check if indexer port is open

        Args:
            inventory_path (str): Indexer inventory.

        Returns:
            str: Os name.
        """
        wait_cycles = 0
        while wait_cycles < cycles:
            ports = Executor.execute_command(inventory_path, 'ss -t -a -n | grep ":9200"').strip().split('\n')
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
