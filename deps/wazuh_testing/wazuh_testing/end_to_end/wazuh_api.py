"""
Wazuh API Operations Module

This module provides functions for handling Wazuh API operations in a HostManager environment.
It includes methods for retrieving API parameters, obtaining authentication tokens,
and retrieving information about Wazuh agents and their vulnerabilities.

Functions:
- get_api_parameters(host_manager): Retrieves Wazuh API parameters.
- get_api_token(host_manager): Retrieves the API token for authentication.
- get_agents_id(host_manager): Retrieves the IDs of Wazuh agents.
- get_agents_vulnerabilities(host_manager): Retrieves vulnerability information for Wazuh agents.

Parameters:
- host_manager (HostManager): An instance of the HostManager class representing the Wazuh environment.
"""
from wazuh_testing.api import make_api_call, get_token_login_api

# Wazuh API Methods
def get_api_parameters(host_manager):
    """
    Retrieves the Wazuh API parameters.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class.

    Returns:
    dict: A dictionary containing Wazuh API parameters, including protocol, host, port, user, and password.
    """

    api_parameters = {
        'protocol': 'https',
        'host': host_manager.get_master_ip(),
        'port': '55000',
        'user': 'wazuh',
        'pass': 'wazuh'
    }
    return api_parameters


def get_api_token(host_manager):
    """
    Retrieves the API token for authentication.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class.

    Returns:
    str: The API token for authentication.
    """
    login_endpoint = '/security/user/authenticate'
    api_parameters = get_api_parameters(host_manager)
    response_token = get_token_login_api(api_parameters['protocol'], api_parameters['host'], api_parameters['port'],
                                         api_parameters['user'], api_parameters['pass'], login_endpoint,
                                         timeout=10, login_attempts=3, sleep_time=1)
    return response_token


def get_agents_id(host_manager):
    """
    Retrieves the IDs of Wazuh agents.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class.

    Returns:
    dict: A dictionary mapping agent names to their corresponding IDs.
    """

    api_token = get_api_token(host_manager)
    agent_output = make_api_call(host_manager.get_master_ip(), endpoint='/agents', token=api_token).json()
    agents_ids = {}
    for agent in agent_output['data']['affected_items']:
        agents_ids[agent['name']] = agent['id']

    return agents_ids


def get_agents_vulnerabilities(host_manager):
    """
    Retrieves vulnerability information for Wazuh agents.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class.

    Returns:
    dict: A dictionary mapping agent names to a list of their vulnerabilities.
    """
    api_token = get_api_token(host_manager)
    agents_ids = get_agents_id(host_manager)
    agents_vuln = {}
    for agent in host_manager.get_group_hosts('agent'):
        agents_vuln[agent] = make_api_call(host_manager.get_master_ip(), endpoint=f"/vulnerability/{agents_ids[agent]}",
                                           token=api_token).json()['data']['affected_items']

    return agents_vuln
