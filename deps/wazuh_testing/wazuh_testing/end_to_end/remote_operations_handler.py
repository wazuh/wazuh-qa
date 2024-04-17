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
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from wazuh_testing.end_to_end.waiters import wait_syscollector_and_vuln_scan
from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.vulnerability_detector import check_vuln_alert_indexer, check_vuln_state_index, \
        load_packages_metadata, get_vulnerabilities_from_states_by_agent, get_vulnerabilities_from_alerts_by_agent, \
        Vulnerability
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


def get_expected_vulnerabilities_for_package(host_manager: HostManager, host: str,
                                             package_id: str, check: Dict) -> Dict:

    package_data = load_packages_metadata()[package_id]
    vulnerabilities_list = []

    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']

    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    package_system = get_package_system(host, host_manager)

    for cve in package_data['CVE']:
        vulnerability = Vulnerability(cve, package_data['package_name'], package_data['package_version'], host_os_arch)
        vulnerabilities_list.append(vulnerability)

    vulnerabilities = sorted(vulnerabilities_list,
                             key=lambda x: (x.cve, x.package_name, x.package_version, x.architecture))

    expected_vuln = {
        'alerts': vulnerabilities if check.get('alerts', True) else [],
        'index': vulnerabilities if check.get('states', True) else []
    }

    return expected_vuln


def filter_vulnerabilities_by_packages(host_manager: HostManager, vulnerabilities: Dict,
                                       packages_data: Dict) -> Dict:
    filtered_vulnerabilities = {}
    for host in vulnerabilities.keys():
        filtered_vulnerabilities[host] = []
        host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
        host_os_arch = host_manager.get_host_variables(host)['architecture']

        package_id = packages_data[host_os_name][host_os_arch]
        package_data = load_packages_metadata()[package_id]
        package_name = package_data['package_name']

        for vulnerability in vulnerabilities[host]:
            if vulnerability.package_name == package_name:
                filtered_vulnerabilities[host].append(vulnerability)

    return filtered_vulnerabilities


def get_expected_vulnerabilities_by_agent(host_manager: HostManager, agents_list: List, packages_data: Dict) -> Dict:
    """
    Get the expected vulnerabilities by agent.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        packages_data (dict): Dictionary containing package data.

    Returns:
        dict: Dictionary containing the expected vulnerabilities by agent.
    """

    expected_vulnerabilities_by_agent = {}
    for agent in agents_list:
        host_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        host_os_arch = host_manager.get_host_variables(agent)['architecture']

        expected_vulnerabilities_by_agent[agent] = []
        package_id = packages_data[host_os_name][host_os_arch]

        expected_vulnerabilities = get_expected_vulnerabilities_for_package(host_manager, agent, package_id,)
        expected_vulnerabilities_by_agent[agent] = expected_vulnerabilities

    return expected_vulnerabilities_by_agent


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


def get_package_uninstallation_name(host: str, package_id: str, host_manager: HostManager,
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
        package_uninstall_name = package_data['uninstall_name']

        return package_uninstall_name
    except KeyError:
        raise ValueError(f"Package for {host_os_name} and {host_os_arch} not found uninstall name.")


def get_package_uninstallation_playbook(host: str, package_id: str, host_manager: HostManager,
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
        package_uninstall_name = package_data['uninstall_custom_playbook']

        return package_uninstall_name
    except KeyError:
        raise ValueError(f"Custom installation playbook for {host_os_name} and {host_os_arch} not found uninstall name.")


def get_package_system(host: str, host_manager: HostManager) -> str:
    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    return system


def get_vulnerabilities(host_manager: HostManager, agent_list, packages_data: Dict,
                          greater_than_timestamp: str = '') -> Dict:

    result = {}
    wait_syscollector_and_vuln_scan(host_manager, TIMEOUT_SYSCOLLECTOR_SCAN, greater_than_timestamp=greater_than_timestamp,
                                    agent_list=agent_list)
    vulnerabilities = get_vulnerabilities_from_states_by_agent(host_manager, agent_list,
                                            greater_than_timestamp=greater_than_timestamp)
    alerts = get_vulnerabilities_from_alerts_by_agent(host_manager, agent_list,
                                                    greater_than_timestamp=greater_than_timestamp)
    package_vulnerabilities = filter_vulnerabilities_by_packages(host_manager, vulnerabilities, packages_data)
    alerts_vulnerabilities = filter_vulnerabilities_by_packages(host_manager, alerts['affected'] , packages_data)
    alerts_vulnerabilities_mitigated = filter_vulnerabilities_by_packages(host_manager, alerts['mitigated'] , packages_data)

    result['index_vulnerabilities'] = package_vulnerabilities
    result['alerts_vulnerabilities'] = alerts_vulnerabilities
    result['mitigated_vulnerabilities'] = alerts_vulnerabilities_mitigated

    return result

def install_package(host: str, operation_data: Dict[str, Any], host_manager: HostManager) -> Dict:
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    result = {
        'success': True,
    }

    logging.info(f"Installing package on {host}")
    package_url = get_package_url_for_host(host, operation_data['package'],
                                           host_manager, operation_data)
    package_system = get_package_system(host, host_manager)

    utc_now_timestamp = datetime.utcnow()
    current_datetime = utc_now_timestamp.strftime("%Y-%m-%dT%H:%M:%S")

    try:
        host_manager.install_package(host, package_url, package_system)
    except Exception as e:
        logging.error(f"Error installing package on {host}: {e}")
        result['success'] = False

    # check_options = operation_data.get('check', {})
    # check_vuln = check_options.get('alerts') or check_options.get('states') if check_options else False
    # if result['success'] and check_vuln:
    #     result['vulnerabilities'] = get_vulnerabilities(host_manager, host,
    #                                                     operation_data['package'],
    #                                                     current_datetime)
    #     result['expected_vulnerabilities'] = get_expected_vulnerabilities_by_agent(host_manager, [host],
    #                                                                             operation_data['package'],
    #                                                                             operation_data['check'])[host]

    return result

def remove_package(host: str, operation_data: Dict[str, Any], host_manager: HostManager) -> Dict:
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    result = {
        'success': True,
    }

    logging.info(f"Removing package on {host}")
    package_system = get_package_system(host, host_manager)

    utc_now_timestamp = datetime.utcnow()
    current_datetime = utc_now_timestamp.strftime("%Y-%m-%dT%H:%M:%S")

    try:
        package_uninstall_name = None
        custom_uninstall_playbook = None
        try:
            package_uninstall_name = get_package_uninstallation_name(host, operation_data['package'],
                                           host_manager, operation_data)
        except ValueError:
            logging.info(f"No uninstall name found for {operation_data['package']}. Searching for custom playbook")
            custom_uninstall_playbook = operation_data['package']['uninstall_playbook'] if 'uninstall_playbook' in operation_data['package'] else None

        host_manager.remove_package(host, package_system, package_uninstall_name, custom_uninstall_playbook)

    except Exception as e:
        logging.error(f"Error removing package on {host}: {e}")
        result['success'] = False

    # check_options = operation_data.get('check', {})
    # check_vuln = check_options.get('alerts') or check_options.get('states') if check_options else False

    # if result['success'] and check_vuln:
    #     result['vulnerabilities'] = get_vulnerabilities(host_manager, host,
    #                                                     operation_data['package'],
    #                                                     greater_than_timestamp=current_datetime)
    #     result['expected_vulnerabilities'] = get_expected_vulnerabilities_by_agent(host_manager, [host],
    #                                                                             operation_data['package'],
    #                                                                             operation_data['check'])[host]

    return result


def update_package(host: str, operation_data: Dict[str, Any], host_manager: HostManager) -> Dict:
    result = {
        'success': True,
        'vulnerabilities': {
            'to': {},
            'from': {}
        },
        'expected_vulnerabilities': {
            'to': {},
            'from': {}
        }
    }

    logging.info(f"Installing package on {host}")
    package_url = get_package_url_for_host(host, operation_data['package']['to'],
                                           host_manager, operation_data)
    package_system = get_package_system(host, host_manager)

    utc_now_timestamp = datetime.utcnow()
    current_datetime = utc_now_timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        host_manager.install_package(host, package_url, package_system)
    except Exception as e:
        logging.error(f"Error installing package on {host}: {e}")
        result['success'] = False

    check_options = operation_data.get('check', {})
    check_vuln = check_options.get('alerts') or check_options.get('states') if check_options else False
    # if result['success'] and check_vuln:
    #     result['vulnerabilities']['to'] = get_vulnerabilities(host_manager, host,
    #                                                       operation_data['package']['to'],
    #                                                       greater_than_timestamp=current_datetime)

    #     result['vulnerabilities']['from'] = get_vulnerabilities(host_manager, host,
    #                                                       operation_data['package']['from'],
    #                                                       greater_than_timestamp=current_datetime)

    #     expected_vulnerabilities_to = get_expected_vulnerabilities_by_agent(host_manager, [host],
    #                                                                         operation_data['package']['to'],
    #                                                                         operation_data['check'])[host]

    #     expected_vulnerabilities_from = get_expected_vulnerabilities_by_agent(host_manager, [host],
    #                                                                         operation_data['package']['from'],
    #                                                                         operation_data['check'])[host]

    #     result['expected_vulnerabilities']['to'] = expected_vulnerabilities_to
    #     result['expected_vulnerabilities']['from'] = expected_vulnerabilities_from

    return result


def launch_remote_operation(host: str, operation_data: Dict[str, Dict], host_manager: HostManager):
    operation = operation_data['operation']
    if operation in globals():
        operation_result = globals()[operation](host, operation_data, host_manager)
        logging.info(f"Operation result: {operation_result}")
        return operation_result
    else:
        raise ValueError(f"Operation {operation} not recognized")


def launch_parallel_operations(task: Dict[str, List], host_manager: HostManager,
                               target_to_ignore: List[str] = None):
    """
    Launch parallel remote operations on multiple hosts.

    Args:
        operation (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """

    hosts_to_ignore = target_to_ignore if target_to_ignore else []
    target = 'agent'
    results = {}
    lock = threading.Lock()

    def launch_and_store_result(args):
        host, task, manager = args
        result = launch_remote_operation(host, task, manager)
        results[task['operation']] = {}
        with lock:
            results[task['operation']][host] = result

    with ThreadPoolExecutor() as executor:
        # Submit tasks asynchronously
        hosts_target = host_manager.get_group_hosts(target)
        hosts_to_ignore = target_to_ignore

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

    logging.info("Results in parallel operations: {}".format(results))

    return results
