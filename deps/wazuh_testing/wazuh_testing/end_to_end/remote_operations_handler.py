"""
Remote Operations Module.
-------------------------

This module provides functions for launching remote operations on hosts and managing vulnerability checks.

It utilizes the Wazuh testing framework, including the HostManager class for handling
remote hosts and various tools for indexer API interactions.

Functions:
    - launch_remote_operation: Launch a remote operation on a specified host.
    - check_vuln_state_index: Check the vulnerability state index for a host.
    - check_vuln_alert_indexer: Check vulnerability alerts in the indexer for a host.
    - check_vuln_alert_api: Check vulnerability alerts via API for a host.
    - launch_remote_sequential_operation_on_agent: Launch sequential remote operations on a specific agent.
    - launch_parallel_operations: Launch parallel remote operations on multiple hosts.

Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""


from typing import Dict, List
from multiprocessing.pool import ThreadPool

from wazuh_testing.end_to_end.indexer_api import get_indexer_values
from wazuh_testing.tools.system import HostManager


def launch_remote_operation(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    """
    Launch a remote operation on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['arch']
    system = host_manager.get_host_variables(host)['os_name']
    operation = operation_data['operation']

    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    if operation == 'install_package':
        package_data = operation_data['package']
        package_url = package_data[host_os_name][host_os_arch]
        host_manager.install_package(host, package_url, system)

    elif operation == 'remove_package':
        package_data = operation_data['package']
        package_name = package_data[host_os_name]
        host_manager.remove_package(host, package_name, system)

    elif operation == 'check_agent_vulnerability':

        if operation_data['parameters']['alert_indexed']:
            check_vuln_alert_indexer(host_manager, operation_data['vulnerability_data'])

        if operation_data['parameters']['api']:
            check_vuln_alert_api(host_manager, operation_data['vulnerability_data'])

        if operation_data['parameters']['state_indice']:
            check_vuln_state_index(host_manager, operation_data['vulnerability_data'])


def check_vuln_state_index(host_manager: HostManager, vulnerability_data: Dict[str, Dict]):
    """
    Check vulnerability state index for a host.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        vulnerability_data (dict): Dictionary containing vulnerability data.

    ToDo:
        Implement the functionality.
    """
    index_vuln_state_content = get_indexer_values(host_manager)


def check_vuln_alert_indexer(host_manager: HostManager, vulnerability_data: Dict[str, Dict]):
    """
    Check vulnerability alerts in the indexer for a host.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        vulnerability_data (dict): Dictionary containing vulnerability data.

    Returns:
        list: List of vulnerability alerts.

    ToDo:
        Implement the functionality.
    """
    indexer_alerts = get_indexer_values(host_manager, index='wazuh-alerts*')

    return indexer_alerts


def check_vuln_alert_api(host_manager: HostManager, vulnerability_data: Dict[str, Dict]):
    """
    Check vulnerability alerts via API for a host.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        vulnerability_data (dict): Dictionary containing vulnerability data.

    ToDo:
        Implement the functionality.
    """
    pass


def launch_remote_sequential_operation_on_agent(agent: str, task_list: List[Dict], host_manager: HostManager):
    """
    Launch sequential remote operations on an agent.

    Args:
        agent (str): The target agent on which to perform the operations.
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    if task_list:
        for task in task_list:
            launch_remote_operation(agent, task, host_manager)


def launch_parallel_operations(task_list: List[Dict], host_manager: HostManager):
    """
    Launch parallel remote operations on multiple hosts.

    Args:
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    for task in task_list:
        parallel_configuration = []
        target = task['target']

        for host in host_manager.get_group_hosts(target):
            parallel_configuration.append((host, task, host_manager))

        with ThreadPool() as pool:
            # Use the pool to map the function to the list of hosts
            pool.starmap(launch_remote_operation, parallel_configuration)
