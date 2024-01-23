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

import os
import json
import logging
from typing import Dict, List
from multiprocessing.pool import ThreadPool
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs, monitoring_events_multihost
from wazuh_testing.end_to_end.waiters import wait_until_vuln_scan_agents_finished
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.end_to_end.logs import truncate_remote_host_group_files
from wazuh_testing.end_to_end.vulnerability_detector import check_vuln_alert_indexer, check_vuln_state_index


def load_packages_metadata():
    """
    Load packages metadata from the packages.json file.
    """
    packages_filepath = os.path.join(os.path.dirname(__file__),
                                     'vulnerability_detector_packages', 'vuln_packages.json')

    with open(packages_filepath, 'r') as packages_file:
        packages_data = json.load(packages_file)

    return packages_data


def install_package(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    logging.critical(f"Installing package on {host}")
    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    install_package_data = operation_data['package']
    package_id = None

    if host_os_name in install_package_data:
        if host_os_arch in install_package_data[host_os_name]:
            package_id = install_package_data[host_os_name][host_os_arch]
        else:
            raise ValueError(f"Package for {host_os_name} and {host_os_arch} not found")

    package_data = load_packages_metadata()[package_id]
    package_url = package_data['urls'][host_os_name][host_os_arch]

    logging.critical(f"Installing package on {host}")
    logging.critical(f"Package URL: {package_url}")

    current_datetime = datetime.utcnow().isoformat()
    host_manager.install_package(host, package_url, system)

    logging.critical(f"Package installed on {host}")

    if operation_data['check']['alerts'] or operation_data['check']['state_index']:
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

        wait_until_vuln_scan_agents_finished(host_manager)

        logging.critical(f"Checking agent vulnerability on {host}")

        results = {
                'evidences': {
                    "alerts_not_found": [],
                    "states_not_found": []
                },
                'checks': {}
        }

        if 'check' in operation_data:
            if operation_data['check']['alerts']:
                logging.critical(f'Checking vulnerability alerts in the indexer for {host}')
                results["alerts_not_found"] = check_vuln_alert_indexer(host_manager, host, package_data,
                                                                       current_datetime)

            if operation_data['check']['state_index']:
                logging.critical(f'Checking vulnerability state index for {host}')
                results["states_not_found"] = check_vuln_state_index(host_manager, host, package_data,
                                                                     current_datetime)

        logging.critical(f"Results: {results}")

        if results['alerts_not_found'] or results['states_not_found']:
            results['checks']['all_successfull'] = False
        else:
            results['checks']['all_successfull'] = True

        return {
                f"{host}": results
            }


def remove_package(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    logging.critical(f"Removing package on {host}")
    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    package_data = operation_data['package']
    package_id = None

    if host_os_name in package_data:
        if host_os_arch in package_data[host_os_name]:
            package_id = package_data[host_os_name][host_os_arch]
        else:
            raise ValueError(f"Package for {host_os_name} and {host_os_arch} not found")

    package_data = load_packages_metadata()[package_id]

    logging.critical(f"Removing package on {host}")
    uninstall_name = package_data['uninstall_name']

    current_datetime = datetime.utcnow().isoformat()
    host_manager.remove_package(host, uninstall_name, system)

    if operation_data['check']['alerts'] or operation_data['check']['state_index']:
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

        wait_until_vuln_scan_agents_finished(host_manager)

        logging.critical(f"Checking agent vulnerability on {host}")

        results = {
                'evidences': {
                    "alerts_not_found": [],
                    "states_found": []
                },
                'checks': {}
        }

        logging.critical("Operation data is: {}".format(package_data))

        if 'check' in operation_data:
            if operation_data['check']['alerts'] or operation_data['check']['states']:
                if operation_data['check']['alerts']:
                    logging.critical(f'Checking vulnerability alerts in the indexer for {host}')
                    results["evidences"]["alerts_not_found"] = check_vuln_alert_indexer(host_manager, host, package_data,
                                                                                        current_datetime,
                                                                                        vuln_mitigated=True)

                if operation_data['check']['state_index']:
                    logging.critical(f'Checking vulnerability state index for {host}')
                    states_not_found = check_vuln_state_index(host_manager, host, package_data,
                                                              current_datetime, return_found=True)

                    results['evidences']["states_found"] = states_not_found

            if results['evidences']['alerts_not_found'] or len(results['evidences']['states_found']) > 0:
                results['checks']['all_successfull'] = False
            else:
                results['checks']['all_successfull'] = True

        return {
                f"{host}": results
            }


def update_package(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    logging.critical(f"Updating package on {host}")

    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    install_package_data_from = operation_data['package']['from']
    install_package_data_to= operation_data['package']['to']

    package_id_from = None
    package_id_to = None

    if host_os_name in install_package_data_from:
        if host_os_arch in install_package_data_from[host_os_name]:
            package_id_from = install_package_data_from[host_os_name][host_os_arch]
        else:
            raise ValueError(f"Package for {host_os_name} and {host_os_arch} not found")

    if host_os_name in install_package_data_to:
        if host_os_arch in install_package_data_to[host_os_name]:
            package_id_to = install_package_data_to[host_os_name][host_os_arch]
        else:
            raise ValueError(f"Package for {host_os_name} and {host_os_arch} not found")

    package_data_from = load_packages_metadata()[package_id_from]
    package_data_to = load_packages_metadata()[package_id_to]

    package_url_from = package_data_from['urls'][host_os_name][host_os_arch]
    package_url_to = package_data_to['urls'][host_os_name][host_os_arch]

    logging.critical(f"Installing package on {host}")
    logging.critical(f"Package URL: {package_url_to}")

    current_datetime = datetime.utcnow().isoformat()
    host_manager.install_package(host, package_url_to, system)

    logging.critical(f"Package installed on {host}")

    if operation_data['check']['alerts'] or operation_data['check']['state_index']:
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

        wait_until_vuln_scan_agents_finished(host_manager)

        logging.critical(f"Checking agent vulnerability on {host}")

        results = {
                'evidences': {
                    "alerts_not_found_from": [],
                    "states_found_from": [],
                    "alerts_not_found_to": [],
                    "states_not_found_to": [],
                },
                'checks': {}
        }

        if 'check' in operation_data:
            if operation_data['check']['alerts']:
                logging.critical(f'Checking vulnerability alerts in the indexer for {host}. Expected CVE mitigation')
                results["evidences"]["alerts_not_found_from"] = check_vuln_alert_indexer(host_manager, host, package_data_from,
                                                                                    current_datetime,
                                                                                    vuln_mitigated=True)

            if operation_data['check']['state_index']:
                logging.critical(f'Checking vulnerability state index for {host}')
                states_not_found = check_vuln_state_index(host_manager, host, package_data_from,
                                                          current_datetime, return_found=True)
                results['evidences']["states_found_from"] = states_not_found

                logging.critical(f'Checking vulnerability alerts in the indexer for {host}. Expected CVE vuln of new package version')

            if operation_data['check']['alerts']:
                logging.critical(f'Checking vulnerability alerts in the indexer for {host}')
                results["alerts_not_found_to"] = check_vuln_alert_indexer(host_manager, host, package_data_to,
                                                                       current_datetime)

            if operation_data['check']['state_index']:
                logging.critical(f'Checking vulnerability state index for {host}')
                results["states_not_found_to"] = check_vuln_state_index(host_manager, host, package_data_to,
                                                                     current_datetime)

        logging.critical(f"Results: {results}")

        if results['evidences']['alerts_not_found_from'] or len(results['evidences']['states_found_from']) > 0 or \
                results['evidences']['alerts_not_found_to'] or results['evidences']['states_not_found_to']:
            results['checks']['all_successfull'] = False
        else:
            results['checks']['all_successfull'] = True

        return {
                f"{host}": results
            }


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
            operation = task['operation']
            if operation in locals():
                locals()[operation](agent, task, host_manager, timestamp)


def launch_remote_operation(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    operation = operation_data['operation']
    if operation in globals():
        operation_result = globals()[operation](host, operation_data, host_manager)
        return operation_result
    else:
        raise ValueError(f"Operation {operation} not recognized")


def launch_parallel_operations(task_list: List[Dict], host_manager: HostManager, target_to_ignore: List[str] = []):
    """
    Launch parallel remote operations on multiple hosts.

    Args:
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    results = {}

    if target_to_ignore:
        for target in results:
            results[target]['checks']['all_successfull'] = False

    def launch_and_store_result(args):
        host, task, manager = args
        result = launch_remote_operation(host, task, manager)
        results.update(result)

    with ThreadPoolExecutor() as executor:
        # Submit tasks asynchronously
        futures = [executor.submit(launch_and_store_result, (host, task, host_manager))
                   for task in task_list for host in host_manager.get_group_hosts(task['target'] - target_to_ignore)]

        # Wait for all tasks to complete
        for future in futures:
            future.result()

    return results
