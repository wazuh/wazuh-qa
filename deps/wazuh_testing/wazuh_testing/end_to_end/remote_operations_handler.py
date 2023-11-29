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

from wazuh_testing.end_to_end.indexer_api import get_indexer_values
from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.wazuh_api import  get_agents_vulnerabilities
from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs_all_agent, monitoring_events_multihost
from wazuh_testing.end_to_end.waiters import wait_until_vuln_scan_agents_finished
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.end_to_end.logs import truncate_remote_host_group_files

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
    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['architecture']
    system = host_manager.get_host_variables(host)['os_name']
    operation = operation_data['operation']


    print("Performing remote operations")

    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]

    if operation == 'install_package':
        print("Installing package")
        package_data = operation_data['package']
        package_url = package_data[host_os_name][host_os_arch]

        if isinstance(package_url, list):
            for package in package_url:
                host_manager.install_package(host, package, system)
        else:
            host_manager.install_package(host, package_url, system)


        TIMEOUT_SYSCOLLECTOR_SCAN = 60
        truncate_remote_host_group_files(host_manager, 'agent', 'logs')

        # Wait until syscollector
        monitoring_data = generate_monitoring_logs_all_agent(host_manager,
                                                        [get_event_regex({'event': 'syscollector_scan_start'}),
                                                        get_event_regex({'event': 'syscollector_scan_end'})],
                                                        [TIMEOUT_SYSCOLLECTOR_SCAN, TIMEOUT_SYSCOLLECTOR_SCAN])

        monitoring_events_multihost(host_manager, monitoring_data)

        truncate_remote_host_group_files(host_manager, 'manager', 'logs')
        # Wait until VD scan
        wait_until_vuln_scan_agents_finished(host_manager)

    elif operation == 'remove_package':
        package_data = operation_data['package']
        package_name = package_data[host_os_name][host_os_arch]
        host_manager.remove_package(host, package_name, system)

        TIMEOUT_SYSCOLLECTOR_SCAN = 60

        truncate_remote_host_group_files(host_manager, 'agent', 'logs')
        # Wait until syscollector
        monitoring_data = generate_monitoring_logs_all_agent(host_manager,
                                                        [get_event_regex({'event': 'syscollector_scan_start'}),
                                                        get_event_regex({'event': 'syscollector_scan_end'})],
                                                        [TIMEOUT_SYSCOLLECTOR_SCAN, TIMEOUT_SYSCOLLECTOR_SCAN])

        monitoring_events_multihost(host_manager, monitoring_data)

        truncate_remote_host_group_files(host_manager, 'manager', 'logs')

        # Wait until VD scan
        wait_until_vuln_scan_agents_finished(host_manager)

    elif operation == 'check_agent_vulnerability':
        if operation_data['parameters']['alert_indexed']:
            check_vuln_alert_indexer(host_manager, operation_data['vulnerability_data'], current_datetime)

        if operation_data['parameters']['state_indice']:
            check_vuln_state_index(host_manager, operation_data['vulnerability_data'], current_datetime)


def check_vuln_state_index(host_manager: HostManager, vulnerability_data: Dict[str, Dict], current_datetime: str = None):
    """
    Check vulnerability state index for a host.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        vulnerability_data (dict): Dictionary containing vulnerability data.

    ToDo:
        Implement the functionality.
    """
    index_vuln_state_content = get_indexer_values(host_manager, index='wazuh-states-vulnerabilities')['hits']['hits']
    expected_alerts_not_found = []

    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        host_os_arch = host_manager.get_host_variables(agent)['architecture']

        if host_os_name in vulnerability_data and host_os_arch in vulnerability_data:
            vulnerabilities = vulnerability_data[host_os_name][host_os_arch]
            for vulnerability in vulnerabilities:

                for indice_vuln in index_vuln_state_content:
                    state_agent = indice_vuln['agent']['name']
                    state_cve = indice_vuln['vulnerability']['enumeration']
                    state_package_name = indice_vuln['package']['name']
                    state_package_version = indice_vuln['agent']['version']
                    found = False

                    if state_agent == agent and state_cve == vulnerability['CVE'] \
                        and state_package_name == vulnerability['PACKAGE_NAME'] and \
                            state_package_version == vulnerability['PACKAGE_VERSION']:
                        found = True

                if not found:
                    expected_alerts_not_found.append(vulnerability)

    assert len(expected_alerts_not_found) == 0, f"Expected alerts were not found {expected_alerts_not_found}"


def detect_alerts_by_agent(alerts, regex, current_datetime=None):
    alerts_vuln_by_agent = {}
    for alert in alerts:
        valid_timestamp = True
        if current_datetime:
            dt = datetime.strptime(alert['_source']['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z")

            # Convert datetime to Unix timestamp (integer)
            timestamp = int(dt.timestamp())
            if timestamp < current_datetime:
                valid_timestamp = False

        if valid_timestamp:
            if re.match(regex, alert['_source']['rule']['description']):
                if 'agent' in alert['_source']:
                    agent = alert['_source']['agent']['name']
                    if agent not in alerts_vuln_by_agent:
                        alerts_vuln_by_agent[agent] = []
                    else:
                        alerts_vuln_by_agent[agent].append(alert)

    return alerts_vuln_by_agent


def check_vuln_alert_indexer(host_manager: HostManager, vulnerability_data: Dict[str, Dict], current_datetime: str = None):
    """
    Check vulnerability alerts in the indexer for a host.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        vulnerability_data (dict): Dictionary containing vulnerability data.

    Returns:
        list: List of vulnerability alerts.
    """
    regex_cve_affects = f"CVE.* affects .*"
    regex_solved_vuln = f"The .* that affected .* was solved due to a package removal"


    indexer_alerts = get_indexer_values(host_manager)['hits']['hits']
    # Get CVE affects alerts for all agents
    detected_vuln_alerts_by_agent = detect_alerts_by_agent(indexer_alerts, regex_cve_affects, current_datetime)
    solved_alerts_by_agent = detect_alerts_by_agent(indexer_alerts, regex_solved_vuln, current_datetime)
    triggered_alerts = detected_vuln_alerts_by_agent
    expected_alerts_not_found = []

    if 'state' in vulnerability_data and not vulnerability_data['state']:
        triggered_alerts = solved_alerts_by_agent

    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        host_os_arch = host_manager.get_host_variables(agent)['architecture']

        if host_os_name in vulnerability_data and host_os_arch in vulnerability_data:
            vulnerabilities = vulnerability_data[host_os_name][host_os_arch]
            for vulnerability in vulnerabilities:
                cve = vulnerability['CVE']
                package = vulnerabilities['PACKAGE']
                version = vulnerabilities['VERSION']
                found = False
                for triggered_alert in triggered_alerts[agent]:
                    if triggered_alert['cve'] == cve and triggered_alert['package'] == package and \
                       triggered_alert['version'] == version:
                        found = True
                if not found:
                    expected_alerts_not_found.append(vulnerability)

    assert len(expected_alerts_not_found) == 0, f"Expected alerts were not found {expected_alerts_not_found}"


def launch_remote_sequential_operation_on_agent(agent: str, task_list: List[Dict], host_manager: HostManager):
    """
    Launch sequential remote operations on an agent.

    Args:
        agent (str): The target agent on which to perform the operations.
        task_list (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """
    # Get the current datetime in UTC
    current_datetime = datetime.now(timezone.utc)

    # Convert datetime to Unix timestamp (integer)
    timestamp = int(current_datetime.timestamp())

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
        parallel_configuration = []
        target = task['target']

        for host in host_manager.get_group_hosts(target):
            parallel_configuration.append((host, task, host_manager))

        with ThreadPool() as pool:
            # Use the pool to map the function to the list of hosts
            pool.starmap(launch_remote_operation, parallel_configuration)
