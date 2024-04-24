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


class WazuhIndexer:

    @staticmethod
    def get_indexer_version(inventory_path) -> str:
        """
        Returns indexer version

        Args:
            inventory_path (str): host's inventory path
        """

        return Executor.execute_command(inventory_path,'cat /usr/share/wazuh-indexer/VERSION')


    @staticmethod
    def areIndexer_internalUsers_complete(inventory_path) -> bool:
        """
        Returns True/False depending on the existance of all the expected internal users

        Args:
            inventory_path (str): host's inventory path
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