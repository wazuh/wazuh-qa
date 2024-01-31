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


STATE_INDEX_NAME = 'wazuh-vulnerabilities-states'


def get_indexer_values(host_manager: HostManager, credentials: dict = {'user': 'admin', 'password': 'changeme'},
                       index: str = 'wazuh-alerts*', greater_than_timestamp=None) -> Dict:
    """
    Get values from the Wazuh Indexer API.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        credentials (Optional): A dictionary containing the Indexer credentials. Defaults to
                                 {'user': 'admin', 'password': 'changeme'}.
        index (Optional): The Indexer index name. Defaults to 'wazuh-alerts*'.
        greater_than_timestamp (Optional): The timestamp to filter the results. Defaults to None.

    Returns:
       Dict: A dictionary containing the values retrieved from the Indexer API.
    """
    logging.debug(f"Getting values from the Indexer API for index {index}.")
    url = f"https://{host_manager.get_master_ip()}:9200/{index}/_search"
    headers = {
        'Content-Type': 'application/json',
    }

    data = {
        "query": {
            "match_all": {}
        }
    }

    if greater_than_timestamp:
        query = {
                "bool": {
                    "must": [
                        {"match_all": {}},
                        {"range": {"@timestamp": {"gte": f"{greater_than_timestamp}"}}}
                    ]
                }
        }

        sort = [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ]

        data['query'] = query
        data['sort'] = sort

    param = {
        'pretty': 'true',
        'size': 10000,
    }

    response = requests.get(url=url, params=param, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']),
                            headers=headers,
                            json=data)

    return response.json()
