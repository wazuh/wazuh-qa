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
    - launch_parallel_operations: Launch parallel remote operations on multiple hosts.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import logging
import threading

from typing import Dict, List, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from wazuh_testing.end_to_end.waiters import wait_syscollector_and_vuln_scan
from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.vulnerability_detector import check_vuln_alert_indexer, check_vuln_state_index, \
        load_packages_metadata, get_vulnerabilities_from_states_by_agent, get_vulnerabilities_from_alerts_by_agent
from wazuh_testing.end_to_end.indexer_api import get_indexer_values
from wazuh_testing.modules.syscollector import TIMEOUT_SYSCOLLECTOR_SCAN

def get_vulnerabilities_not_found(vulnerabilities_found: List, expected_vulnerabilities: List) -> List:
    """
    Get the vulnerabilities not found in the list of expected vulnerabilities.

    Args:
        vulnerabilities_found (list): List of vulnerabilities found.
        expected_vulnerabilities (list): List of expected vulnerabilities.

    Returns:
        list: List of vulnerabilities not found.
    """
    vulnerabilities_not_found = []
    for vulnerability in expected_vulnerabilities:
        if vulnerability not in vulnerabilities_found:
            vulnerabilities_not_found.append(vulnerability)

    return vulnerabilities_not_found


def get_missing_vulnerabilities(vulnerabilities_by_agent: Dict, expected_vulnerabilities_by_agent: Dict) -> Dict:  
    """
    Get the missing vulnerabilities in the list of expected vulnerabilities.

    Args:
        vulnerabilities_by_agent (dict): Dictionary containing the vulnerabilities found by agent.
        expected_vulnerabilities_by_agent (dict): Dictionary containing the expected vulnerabilities by agent.

    Returns:
        dict: Dictionary containing the missing vulnerabilities.
    """
    missing_vulnerabilities = {}
    for agent, vulnerabilities in expected_vulnerabilities_by_agent.items():
        missing_vulnerabilities[agent] = get_vulnerabilities_not_found(vulnerabilities_by_agent[agent], vulnerabilities)

    return missing_vulnerabilities


def calculate_expected_vulnerabilities_by_agent(host_manager: HostManager, packages_data: Dict) -> Dict:
    """
    Calculate the expected vulnerabilities by agent.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        packages_data (dict): Dictionary containing package data.

    Returns:
        dict: Dictionary containing the expected vulnerabilities by agent.
    """
    expected_vulnerabilities_by_agent = {}
    for agent in host_manager.get_group_hosts('agent'):
        expected_vulnerabilities_by_agent[agent] = []
        for package_id in packages_data:
            expected_vulnerabilities_by_agent[agent].extend(packages_data[package_id]['CVE'])

    return expected_vulnerabilities_by_agent



def check_vulnerabilities_in_environment(host_manager: HostManager, packages_data: Dict, greater_than_timestamp: str,
                                         check_alerts: bool = True, check_states: bool = True) -> Dict:

    # Set-TimeZone -Id "UTC"

    # Wait for syscollector and vulnerability scan to finish
    wait_syscollector_and_vuln_scan(host_manager, TIMEOUT_SYSCOLLECTOR_SCAN, 
                                    greater_than_timestamp=greater_than_timestamp)

    vulnerabilities_by_agent = get_vulnerabilities_from_states_by_agent(host_manager, host_manager.get_group_hosts('agent'), 
                                                                        greater_than_timestamp=greater_than_timestamp)

    alerts_vulnerabilities_by_agent = get_vulnerabilities_from_alerts_by_agent(host_manager, host_manager.get_group_hosts('agent'),
                                                                               greater_than_timestamp=greater_than_timestamp)

    expected_vulnerabilities_index_by_agent = calculate_expected_vulnerabilities_by_agent(host_manager, packages_data)
    expected_vulnerabilities_alerts_by_agent = calculate_expected_vulnerabilities_alerts_by_agent(host_manager, packages_data)

    missing_vulnerabilities = get_missing_vulnerabilities(vulnerabilities_by_agent, expected_vulnerabilities_index_by_agent)
    missing_alerts = get_missing_vulnerabilities(alerts_vulnerabilities_by_agent, expected_vulnerabilities_alerts_by_agent)

    return {
        'missing_vulnerabilities': missing_vulnerabilities,
        'missing_alerts': missing_alerts
    }

def check_vulnerability_alerts(results: Dict, check_data: Dict, current_datetime: str, host_manager: HostManager,
                               host: str,
                               package_data: Dict,
                               operation: str = 'install') -> None:

    # Get all the alerts generated in the timestamp
    vulnerability_alerts = {}
    vulnerability_alerts_mitigated = {}
    vulnerability_index = {}

    for agent in host_manager.get_group_hosts('agent'):
        agent_all_alerts = parse_vulnerability_detector_alerts(get_indexer_values(host_manager,
                                              greater_than_timestamp=current_datetime,
                                              agent=agent)['hits']['hits'])

        agent_all_vulnerabilities = get_indexer_values(host_manager, greater_than_timestamp=current_datetime,
                                                       agent=agent,
                                                       index='wazuh-states-vulnerabilities')['hits']['hits']

        vulnerability_alerts[agent] = agent_all_alerts['affected']
        vulnerability_alerts_mitigated[agent] = agent_all_alerts['mitigated']

        vulnerability_index[agent] = agent_all_vulnerabilities

    results['evidences']['all_alerts_found'] = vulnerability_alerts
    results['evidences']['all_alerts_found_mitigated'] = vulnerability_alerts_mitigated
    results['evidences']['all_states_found'] = vulnerability_index

    # Check unexpected alerts. For installation/removal non vulnerable package
    if 'no_alerts' in check_data and check_data['no_alerts']:
        logging.info(f'Checking unexpected vulnerability alerts in the indexer for {host}')
        results['evidences']["alerts_found_unexpected"] = {
                "mitigated": vulnerability_alerts_mitigated,
                "vulnerabilities": vulnerability_alerts
        }
        if len(results['evidences']['alerts_found_unexpected'].get('mitigated', [])) > 0 or \
                len(results['evidences']['alerts_found_unexpected'].get('vulnerabilities', [])) > 0:
            results['checks']['all_successfull'] = False

    # Check expected alerts
    elif check_data['alerts']:
        logging.info(f'Checking vulnerability alerts for {host}')
        if operation == 'update' or operation == 'remove':
            evidence_key = "alerts_not_found_from" if operation == 'update' else "alerts_not_found"
            package_data_to_use = package_data['from'] if operation == 'update' else package_data
            # Check alerts from previous package are mitigated
            results['evidences'][evidence_key] = check_vuln_alert_indexer(vulnerability_alerts_mitigated,
                                                                          host,
                                                                          package_data_to_use,
                                                                          current_datetime)
        elif operation == 'install' or operation == 'update':
            # Check alerts from new package are found
            evidence_key = "alerts_not_found_to" if operation == 'update' else "alerts_not_found"
            package_data_to_use = package_data['to'] if operation == 'update' else package_data
            results['evidences'][evidence_key] = check_vuln_alert_indexer(vulnerability_alerts,
                                                                          host,
                                                                          package_data_to_use,
                                                                          current_datetime)

        if len(results['evidences'].get('alerts_not_found_from', [])) > 0 or \
                len(results['evidences'].get('alerts_not_found_to', [])) > 0 or \
                len(results['evidences'].get('alerts_not_found', [])) > 0:
            results['checks']['all_successfull'] = False

    # Check unexpected states
    if 'no_indices' in check_data and check_data['no_indices']:
        logging.info(f'Checking vulnerability state index for {host}')
        results['evidences']["states_found_unexpected"] = vulnerability_index

        if len(results['evidences']['states_found_unexpected']) > 0:
            results['checks']['all_successfull'] = False

    elif check_data['state_index']:
        if operation == 'update' or operation == 'remove':
            evidence_key = 'states_found_unexpected_from' if operation == 'update' else 'states_found_unexpected'
            package_data_to_use = package_data['from'] if operation == 'update' else package_data
            # Check states from previous package are mitigated
            results['evidences'][evidence_key] = check_vuln_state_index(host_manager, host, package_data_to_use,
                                                                        current_datetime)
            if len(results['evidences'][evidence_key]) != len(package_data_to_use['CVE']):
                results['checks']['all_successfull'] = False

        elif operation == 'install' or operation == 'update':
            # Check states from new package are found
            evidence_key = 'states_not_found_to' if operation == 'update' else 'states_not_found'
            package_data_to_use = package_data['to'] if operation == 'update' else package_data
            results['evidences'][evidence_key] = check_vuln_state_index(host_manager, host, package_data_to_use,
                                                                        current_datetime)

            if len(results['evidences'][evidence_key]) != 0:
                results['checks']['all_successfull'] = False


def get_package_url_for_host(host: str, package_id: str, host_manager: HostManager, 
                             operation_data: Dict[str, Any]) -> str:

    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']

    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    install_package_data = operation_data['package']
    
    try:
        package_id = install_package_data[host_os_name][host_os_arch]
        package_data = load_packages_metadata()[package_id]
        package_url = package_data['urls'][host_os_name][host_os_arch]

        return package_url
    except KeyError:
        raise ValueError(f"Package for {host_os_name} and {host_os_arch} not found. Maybe {host} OS is not supported.")

def get_package_system(host: str, host_manager: HostManager) -> str:
    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    return system

def install_package(host: str, operation_data: Dict[str, Any], host_manager: HostManager) -> bool:
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    print("Install package")
    install_result = True
    logging.info(f"Installing package on {host}")
    package_url = get_package_url_for_host(host, operation_data['package'], 
                                           host_manager, operation_data)
    package_system = get_package_system(host, host_manager)
    try:
        r = host_manager.install_package(host, package_url, package_system)
        print(r)
    except Exception as e:
        logging.error(f"Error installing package on {host}: {e}")
        install_result = False

    return install_result

def remove_package(host: str, operation_data: Dict[str, Any], host_manager: HostManager):
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    remove_result = True
    logging.info(f"Removing package on {host}")
    package_system = get_package_system(host, host_manager)
    try:
        package_uninstall_name = operation_data['package']['uninstall_name'] if 'uninstall_name' in operation_data['package'] else None
        custom_uninstall_playbook = operation_data['package']['uninstall_playbook'] if 'uninstall_playbook' in operation_data['package'] else None
        host_manager.remove_package(host, package_system, package_uninstall_name, custom_uninstall_playbook)
    except Exception as e:
        logging.error(f"Error installing package on {host}: {e}")
        remove_result = False

    return remove_result


def launch_remote_operation(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    operation = operation_data['operation']
    if operation in globals():
        operation_result = globals()[operation](host, operation_data, host_manager)
        logging.info(f"Operation result: {operation_result}")
        return operation_result
    else:
        raise ValueError(f"Operation {operation} not recognized")


def launch_parallel_operations(task_list: Dict[str, List], host_manager: HostManager, 
                               target_to_ignore: List[str] = []):
    """
    Launch parallel remote operations on multiple hosts.

    Args:
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    results = {}
    lock = threading.Lock()

    def launch_and_store_result(args):
        host, task, manager = args
        result = launch_remote_operation(host, task, manager)

        with lock:
            if host not in results:
                results[host] = []

            results[host].append({task['operation']: result})


    with ThreadPoolExecutor() as executor:
        # Submit tasks asynchronously
        for target, tasks in task_list.items():
            hosts_target = host_manager.get_group_hosts(target)
            hosts_to_ignore = target_to_ignore
            for task in tasks:
                futures = []

                # Calculate the hosts to ignore based on previous operations results
                if target_to_ignore:
                    hosts_target = [host for host in hosts_target if host not in target_to_ignore]

                logging.info(f"Launching operation {task['operation']} on {hosts_target}")

                for host in hosts_target:
                    futures.append(executor.submit(launch_and_store_result, (host, task, host_manager)))

                # Wait for all tasks to complete
                for future in futures:
                    future.result()

                # If the operation is not successful, stop the execution of the rest of the operations in host 
                for host, operation_results in results.items():
                    last_operation_result = operation_results[-1]
                    if not all(last_operation_result.values()):
                        logging.critical(f"Operation {last_operation_result} failed."
                                         f"Stopping execution of the rest of the operations in host {host}")
                        hosts_to_ignore.append(host)


    logging.info("Results in parallel operations: {}".format(results))

    return results
