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


WAZUH_STATES_VULNERABILITIES_INDEXNAME = 'wazuh-states-vulnerabilities'


def create_vulnerability_states_indexer_filter(target_agent: str = None,
                                               greater_than_timestamp: str = None) -> dict:
    """Create a filter for the Indexer API for the vulnerability state index.

    Args:
        target_agent: The target agent to filter on.
        greater_than_timestamp: The timestamp to filter on.

    Returns:
        dict: A dictionary containing the filter.
    """
    timestamp_filter = None
    if greater_than_timestamp:
        timestamp_filter = {
                'greater_than_timestamp': greater_than_timestamp,
                'timestamp_name': 'vulnerability.detected_at'
        }

    return _create_filter(target_agent, timestamp_filter)


def create_alerts_filter(target_agent: str = None, greater_than_timestamp: str = None) -> dict:
    """Create a filter for the Indexer API for the alerts index.

    Args:
        target_agent: The target agent to filter on.
        greater_than_timestamp: The timestamp to filter on.

    Returns:
        dict: A dictionary containing the filter.
    """
    timestamp_filter = None
    if greater_than_timestamp:
        timestamp_filter = {
                'greater_than_timestamp': greater_than_timestamp,
                'timestamp_name': '@timestamp'
        }

    return _create_filter(target_agent, timestamp_filter)


def _create_filter(target_agent: str = None, timestamp_filter: dict = None) -> dict:
    """Create a filter for the Indexer API.

    Args:
        target_agent: The target agent to filter on.
        greater_than_timestamp: The timestamp to filter on.
        timestamp_field: The timestamp field to filter on.

    Returns:
        dict: A dictionary containing the filter.
    """
    filter = {
        'bool': {
            'must': []
        }
    }
    if timestamp_filter:
        timestamp_field = timestamp_filter['timestamp_name']
        greater_than_timestamp = timestamp_filter['greater_than_timestamp']
        filter['bool']['must'].append({'range': {timestamp_field: {'gte': greater_than_timestamp}}})
    if target_agent:
        filter['bool']['must'].append({'match': {'agent.name': target_agent}})

    return filter


def get_indexer_values(host_manager: HostManager, credentials: dict = {'user': 'admin', 'password': 'changeme'},
                       index: str = 'wazuh-alerts*', filter: dict = None, size: int = 10000) -> Dict:
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

    data = {}
    param = {'size': size}
    headers = {'Content-Type': 'application/json'}

    if filter:
        data['query'] = filter

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
