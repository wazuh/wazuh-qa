"""
Wazuh Elasticsearch Indexer Module.
-----------------------------------

This module provides functions to interact with the Wazuh Elasticsearch indexer API.

Functions:
    - get_indexer_values: Retrieves values from the Elasticsearch indexer API.

Usage Example:
    import requests
    from typing import Dict
    from wazuh_testing.tools.system import HostManager

    # Usage of get_indexer_values
    host_manager = HostManager()
    credentials = {'user': 'admin', 'password': 'changeme'}
    index = 'wazuh-alerts*'
    response_data = get_indexer_values(host_manager, credentials, index)


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import requests
from typing import Dict

from wazuh_testing.tools.system import HostManager


STATE_INDEX_NAME = 'wazuh-vulnerabilities-states'


def get_indexer_values(host_manager: HostManager, credentials: dict = {'user': 'admin', 'password': 'changeme'}, index: str = 'wazuh-alerts*') -> Dict:
    """
    Get values from the Wazuh Elasticsearch indexer API.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        credentials (Optional): A dictionary containing the Elasticsearch credentials. Defaults to
                                 {'user': 'admin', 'password': 'changeme'}.
        index (Optional): The Elasticsearch index name. Defaults to 'wazuh-alerts*'.

    Returns:
        str: The response text from the indexer API.
    """
    url = f"https://{host_manager.get_master_ip()}:9200/{index}_search?"
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url=url, params={'pretty': 'true'}, json=query, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']))
    return response.json()

