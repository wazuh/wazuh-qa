"""
Module Name: indexer_api

Description:
    This module provides functions for interacting with the Wazuh Elasticsearch indexer API,
    specifically for retrieving vulnerability state information.

Constants:
    - STATE_INDEX_NAME: The name of the index used for storing Wazuh vulnerabilities states.

Functions:
    1. get_indexer_values(host_manager, credentials={'user': 'admin', 'password': 'changeme'}, index='wazuh-alerts*') -> str:
        Get values from the Wazuh Elasticsearch indexer API.

        Args:
            host_manager: An instance of the HostManager class containing information about hosts.
            credentials (Optional): A dictionary containing the Elasticsearch credentials. Defaults to
                                     {'user': 'admin', 'password': 'changeme'}.
            index (Optional): The Elasticsearch index name. Defaults to 'wazuh-alerts*'.

        Returns:
            str: The response text from the indexer API.

Module Usage:
    This module can be used to retrieve information from the Wazuh Elasticsearch indexer API, specifically for
    vulnerability states.
"""
import requests

from wazuh_testing.tools.system import HostManager


STATE_INDEX_NAME = 'wazuh-vulnerabilities-states'


def get_indexer_values(host_manager: HostManager, credentials: dict = {'user': 'admin', 'password': 'changeme'}, index: str = 'wazuh-alerts*') -> str:
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
    return response.text

