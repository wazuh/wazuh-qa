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

import re
from typing import Dict, List
from multiprocessing.pool import ThreadPool
from datetime import datetime, timezone
import logging

from wazuh_testing.end_to_end.indexer_api import get_indexer_values
from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.wazuh_api import  get_agents_vulnerabilities
from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs, monitoring_events_multihost
from wazuh_testing.end_to_end.waiters import wait_until_vuln_scan_agents_finished
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.end_to_end.logs import truncate_remote_host_group_files
from wazuh_testing.end_to_end.vulnerability_detector import check_vuln_alert_indexer, check_vuln_state_index


def launch_remote_operation(host: str, operation_data: Dict[str, Dict], host_manager: HostManager,
                            current_datetime: str = None):
    """
    Launch a remote operation on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    logging.critical(f"Launching remote operation: {operation_data}")

    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']
    operation = operation_data['operation']

    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    if operation == 'install_package':
        logging.critical(f"Installing package on {host}")

        package_data = operation_data['package']
        package_url = package_data[host_os_name][host_os_arch]

        if isinstance(package_url, list):
            for package in package_url:
                host_manager.install_package(host, package, system)
        else:
            host_manager.install_package(host, package_url, system)

        logging.critical(f"Package installed on {host}")
        logging.critical(f"Waiting for syscollector scan to finish on {host}")

        TIMEOUT_SYSCOLLECTOR_SCAN = 80

        truncate_remote_host_group_files(host_manager, 'agent', 'logs')

        # Wait until syscollector
        monitoring_data = generate_monitoring_logs(host_manager,
                                                   [get_event_regex({'event': 'syscollector_scan_start'}),
                                                    get_event_regex({'event': 'syscollector_scan_end'})],
                                                   [TIMEOUT_SYSCOLLECTOR_SCAN, TIMEOUT_SYSCOLLECTOR_SCAN],
                                                   host_manager.get_group_hosts('agent'))

        result = monitoring_events_multihost(host_manager, monitoring_data)

        logging.critical(f"Syscollector scan finished with result: {result}")

        truncate_remote_host_group_files(host_manager, 'manager', 'logs')

        logging.critical(f"Waiting for vulnerability scan to finish on {host}")

        # Wait until VD scan
        wait_until_vuln_scan_agents_finished(host_manager)

    elif operation == 'remove_package':
        logging.critical(f"Removing package on {host}")
        package_data = operation_data['package']
        package_name = package_data[host_os_name][host_os_arch]
        host_manager.remove_package(host, package_name, system)

        TIMEOUT_SYSCOLLECTOR_SCAN = 60

        truncate_remote_host_group_files(host_manager, 'agent', 'logs')
        # Wait until syscollector
        monitoring_data = generate_monitoring_logs(host_manager,
                                                        [get_event_regex({'event': 'syscollector_scan_start'}),
                                                        get_event_regex({'event': 'syscollector_scan_end'})],
                                                        [TIMEOUT_SYSCOLLECTOR_SCAN, TIMEOUT_SYSCOLLECTOR_SCAN], host_manager.get_group_hosts('agent'))

        monitoring_events_multihost(host_manager, monitoring_data)

        truncate_remote_host_group_files(host_manager, 'manager', 'logs')

        # Wait until VD scan
        wait_until_vuln_scan_agents_finished(host_manager)

    elif operation == 'check_agent_vulnerability':
        logging.critical(f"Checking agent vulnerability on {host}")

        results = {
            "alerts_not_found": [],
            "states_not_found": []
        }

        if operation_data['parameters']['alert_indexed']:
            logging.critical(f'Checking vulnerability alerts in the indexer for {host}')
            results["alerts_not_found"] = check_vuln_alert_indexer(host_manager, operation_data['vulnerability_data'], current_datetime)

        if operation_data['parameters']['state_indice']:
            logging.critical(f'Checking vulnerability state index for {host}')
            results["states_not_found"] = check_vuln_state_index(host_manager, operation_data['vulnerability_data'], current_datetime)

        assert len(results["alerts_not_found"]) == 0 and len(results["states_not_found"]) == 0, \
            f"Vulnerability alerts or states not found for {host}: {results}"


def launch_remote_sequential_operation_on_agent(agent: str, task_list: List[Dict], host_manager: HostManager):
    """
    Launch sequential remote operations on an agent.

    Args:
        agent (str): The target agent on which to perform the operations.
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    # Convert datetime to Unix timestamp (integer)
    timestamp = datetime.utcnow().isoformat()

    if task_list:
        for task in task_list:
            launch_remote_operation(agent, task, host_manager, timestamp)


def launch_parallel_operations(task_list: List[Dict], host_manager: HostManager):
    """
    Launch parallel remote operations on multiple hosts.

    Args:
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    for task in task_list:
        logging.critical(f"Launching parallel task: {task}")
        parallel_configuration = []
        target = task['target']

        for host in host_manager.get_group_hosts(target):
            parallel_configuration.append((host, task, host_manager))

        with ThreadPool() as pool:
            # Use the pool to map the function to the list of hosts
            pool.starmap(launch_remote_operation, parallel_configuration)
