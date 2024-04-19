"""
Wazuh API Indexer Module.
-----------------------------------

This module provides functions to interact with the Wazuh Indexer API.

Functions:
    - get_indexer_values: Retrieves values from the Indexer API.

Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import requests
import logging
from typing import Dict

from wazuh_testing.tools.system import HostManager


STATE_INDEX_NAME = 'wazuh-states-vulnerabilities'


def get_indexer_values(host_manager: HostManager, credentials: dict = {'user': 'admin', 'password': 'changeme'},
                       index: str = 'wazuh-alerts*', filter: dict | None = None, size: int = 10000) -> Dict:
    """
    Get values from the Wazuh Indexer API.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        credentials (Optional): A dictionary containing the Indexer credentials. Defaults to
                                 {'user': 'admin', 'password': 'changeme'}.
        index (Optional): The Indexer index name. Defaults to 'wazuh-alerts*'.
        filter (Optional): A dictionary containing the query filter. Defaults to None.
        size (Optional): The number of results to retrieve. Defaults to 10000.

    Returns:
       Dict: A dictionary containing the values retrieved from the Indexer API.
    """
    logging.info(f"Getting values from the Indexer API for index {index}")

    url = f"https://{host_manager.get_master_ip()}:9200/{index}/_search"
    headers = {
        'Content-Type': 'application/json',
    }

    data = {}
    if filter:
        data['query'] = filter

    param = {
        'size': size,
    }

    response = requests.get(url=url, params=param, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']),
                            headers=headers,
                            json=data)

    return response.json()


def delete_index(host_manager: HostManager, credentials: dict = {'user': 'admin', 'password': 'changeme'},
                 index: str = 'wazuh-alerts*'):
    """
    Delete index from the Wazuh Indexer API.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        credentials (Optional): A dictionary containing the Indexer credentials. Defaults to
                                 {'user': 'admin', 'password': 'changeme'}.
        index (Optional): The Indexer index name. Defaults to 'wazuh-alerts*'.
    """
    logging.info(f"Deleting {index} index")

    url = f"https://{host_manager.get_master_ip()}:9200/{index}/"
    headers = {
        'Content-Type': 'application/json',
    }

    requests.delete(url=url, verify=False,
                    auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']), headers=headers)
