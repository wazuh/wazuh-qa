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
import logging
from typing import Dict, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from wazuh_testing.modules.syscollector import TIMEOUT_SYSCOLLECTOR_SHORT_SCAN
from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs, monitoring_events_multihost
from wazuh_testing.end_to_end.waiters import wait_until_vuln_scan_agents_finished
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.end_to_end.logs import truncate_remote_host_group_files
from wazuh_testing.end_to_end.vulnerability_detector import check_vuln_alert_indexer, check_vuln_state_index, \
        load_packages_metadata, get_vulnerabilities_alerts_indexer, get_indexer_values


def wait_syscollector_and_vuln_scan(host_manager: HostManager, host: str,  operation_data: Dict,
                                    current_datetime: str = '') -> None:
    logging.info(f"Waiting for syscollector scan to finish on {host}")

    timeout_syscollector_scan = TIMEOUT_SYSCOLLECTOR_SHORT_SCAN if 'timeout_syscollector_scan' not in \
        operation_data else operation_data['timeout_syscollector_scan']

    # Wait until syscollector
    monitoring_data = generate_monitoring_logs(host_manager,
                                               [get_event_regex({'event': 'syscollector_scan_start'}),
                                                get_event_regex({'event': 'syscollector_scan_end'})],
                                               [timeout_syscollector_scan, timeout_syscollector_scan],
                                               host_manager.get_group_hosts('agent'),
                                               greater_than_timestamp=current_datetime)

    monitoring_events_multihost(host_manager, monitoring_data)

    logging.critical(f"Waiting for vulnerability scan to finish on {host}")

    wait_until_vuln_scan_agents_finished(host_manager)

    logging.critical(f"Checking agent vulnerability on {host}")


def check_vulnerability_alerts(results: Dict, check_data: Dict, current_datetime: str, host_manager: HostManager,
                               host: str,
                               package_data: Dict,
                               operation: str = 'install') -> None:

    # In case of update, we need to not expect vulnerabilities from previous package and expect vulnerabilities from
    # new package

    if update:
        package_data_from = package_data['from']
        package_data_to = package_data['to']
        vulnerabilities_from = package_data_from['vulnerabilities']
        vulnerabilities_to = package_data_to['vulnerabilities']

        states_vulnerabilities_expected = vulnerabilities_to
        states_vulnerabilities_not_expected = vulnerabilities_from

        # Alerts from previous package should be mitigated


    else:
        states_vulnerabilities_expected = package_data['vulnerabilities']
        states_vulnerabilities_not_expected = []





    # Get all the alerts generated in the timestamp
    vulnerability_alerts = get_vulnerabilities_alerts_indexer(host_manager, host, current_datetime)
    vulnerability_alerts_mitigated = get_vulnerabilities_alerts_indexer(host_manager, host, current_datetime, True)

    vulnerability_index = get_indexer_values(host_manager, index='wazuh-vulnerability-detector',
                                             greater_than_timestamp=current_datetime)['hits']['hits']

    results['checks']['alerts_found'] = vulnerability_alerts
    results['checks']['states_found'] = vulnerability_index

    # Check unexpected alerts. For installation/removel non vulnerable package
    if check_data['no_alerts']:
        logging.critical(f'Checking unexpected vulnerability alerts in the indexer for {host}')
        results['evidences']["alerts_found_unexpected"] = {
                "mitigated": vulnerability_alerts_mitigated,
                "vulnerabilities": vulnerability_alerts
        }
        if len(results['evidences']['alerts_found_unexpected'].get('mitigated', [])) > 0 or \
                len(results['evidences']['alerts_found_unexpected'].get('vulnerabilities', [])) > 0:
            results['checks']['all_successfull'] = False

    # Check expected alerts
    elif check_data['alerts']:
        logging.critical(f'Checking vulnerability alerts for {host}')
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
    if check_data['no_indices']:
        logging.critical(f'Checking vulnerability state index for {host}')
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
            if len(results['evidences'][evidence_key]) != len(package_data_to_use['vulnerabilities']):
                results['checks']['all_successfull'] = False

        elif operation == 'install' or operation == 'update':
            # Check states from new package are found
            evidence_key = 'states_not_found_to' if operation == 'update' else 'states_not_found'
            package_data_to_use = package_data['to'] if operation == 'update' else package_data
            results['evidences'][evidence_key] = check_vuln_state_index(host_manager, host, package_data_to_use,
                                                                        current_datetime)

            if len(results['evidences'][evidence_key]) != 0:
                results['checks']['all_successfull'] = False


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
    results = {
            'evidences': {
                "alerts_not_found": [],
                "states_not_found": [],
                "alerts_found": [],
                "states_found": [],
                "alerts_found_unexpected": [],
                "states_found_unexpected": []
            },
            'checks': {}
    }

    logging.info(f"Installing package on {host}")

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

    logging.info(f"Installing package on {host}")
    logging.info(f"Package URL: {package_url}")

    current_datetime = datetime.utcnow().isoformat()

    host_manager.install_package(host, package_url, system)

    logging.info(f"Package {package_url} installed on {host}")

    logging.info(f"Package installed on {host}")

    results['checks']['all_successfull'] = True

    wait_is_required = 'check' in operation_data and (operation_data['check']['alerts'] or
                                                      operation_data['check']['state_index'] or
                                                      operation_data['check']['no_alerts'] or
                                                      operation_data['check']['no_indices'])

    if wait_is_required:
        wait_syscollector_and_vuln_scan(host_manager, host, operation_data, current_datetime)

        check_vulnerability_alerts(results, operation_data['check'], current_datetime, host_manager, host,
                                   package_data, operation='install')

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
    results = {
            'evidences': {
                "alerts_not_found": [],
                "states_not_found": [],
                "alerts_found": [],
                "states_found": [],
                "alerts_found_unexpected": [],
                "states_found_unexpected": []
            },
            'checks': {}
    }
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

    current_datetime = datetime.utcnow().isoformat()

    logging.critical(f"Removing package on {host}")
    if 'uninstall_name' in package_data:
        uninstall_name = package_data['uninstall_name']
        host_manager.remove_package(host, system, package_uninstall_name=uninstall_name)
    elif 'uninstall_custom_playbook' in package_data:
        host_manager.remove_package(host, system, custom_uninstall_playbook=package_data['uninstall_custom_playbook'])

    wait_is_required = 'check' in operation_data and (operation_data['check']['alerts'] or
                                                      operation_data['check']['state_index'] or
                                                      operation_data['check']['no_alerts'] or
                                                      operation_data['check']['no_indices'])

    if wait_is_required:
        wait_syscollector_and_vuln_scan(host_manager, host, operation_data, current_datetime)

        check_vulnerability_alerts(results, operation_data['check'], current_datetime, host_manager, host,
                                   package_data, operation='remove')

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
    results = {
            'evidences': {
                "alerts_not_found_from": [],
                'alerts_found_from': [],
                "alerts_found": [],
                "states_found": [],
                "alerts_found_unexpected": [],
                "states_found_unexpected": []
            },
            'checks': {}
    }

    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    install_package_data_from = operation_data['package']['from']
    install_package_data_to = operation_data['package']['to']

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

    package_url_to = package_data_to['urls'][host_os_name][host_os_arch]

    logging.critical(f"Installing package on {host}")
    logging.critical(f"Package URL: {package_url_to}")

    current_datetime = datetime.utcnow().isoformat()
    host_manager.install_package(host, package_url_to, system)

    logging.critical(f"Package {package_url_to} installed on {host}")

    logging.critical(f"Package installed on {host}")

    wait_is_required = 'check' in operation_data and (operation_data['check']['alerts'] or
                                                      operation_data['check']['state_index'] or
                                                      operation_data['check']['no_alerts'] or
                                                      operation_data['check']['no_indices'])
    if wait_is_required:
        wait_syscollector_and_vuln_scan(host_manager, host, operation_data, current_datetime)

        check_vulnerability_alerts(results, operation_data['check'], current_datetime, host_manager, host,
                                   package_data_from, operation='update')
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
        logging.critical(f"Operation result: {operation_result}")
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
        futures = []
        for task in task_list:
            hosts_target = host_manager.get_group_hosts(task['target'])
            if target_to_ignore:
                hosts_target = [host for host in hosts_target if host not in target_to_ignore]

            logging.info("Hosts target after removing ignored targets: {}".format(hosts_target))

            for host in hosts_target:
                futures.append(executor.submit(launch_and_store_result, (host, task, host_manager)))

        # Wait for all tasks to complete
        for future in futures:
            future.result()

    logging.info("Results in parallel operations: {}".format(results))

    return results
