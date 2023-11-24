"""
Remote Operations Module.
-------------------------

This module provides functions for launching remote operations on hosts and managing vulnerability checks. It utilizes the Wazuh testing framework, including the HostManager class for handling remote hosts and various tools for indexer API interactions.

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
from wazuh_testing.end_to_end.wazuh_api import  get_agents_vulnerabilities
from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs_all_agent, monitoring_events_multihost
from wazuh_testing.end_to_end.waiters import wait_until_vuln_scan_agents_finished
from wazuh_testing.end_to_end.regex import get_event_regex


def launch_remote_operation(host: str, operation_data: Dict[str,Dict], host_manager: HostManager):
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
        host_manager.install_package(host, package_url, system)
        TIMEOUT_SYSCOLLECTOR_SCAN = 60

        # Wait until syscollector
        monitoring_data = generate_monitoring_logs_all_agent(host_manager,
                                                        [get_event_regex({'event': 'syscollector_scan_start'}),
                                                        get_event_regex({'event': 'syscollector_scan_end'})],
                                                        [TIMEOUT_SYSCOLLECTOR_SCAN, TIMEOUT_SYSCOLLECTOR_SCAN])

        monitoring_events_multihost(host_manager, monitoring_data)

        # Wait until VD scan
        wait_until_vuln_scan_agents_finished(host_manager)


    elif operation == 'remove_package':
        print("Removing package")
        package_data = operation_data['package']
        package_name = package_data[host_os_name][host_os_arch]
        host_manager.remove_package(host, package_name, system)

    elif operation == 'check_agent_vulnerability':
        print("Check agent vuln")
        if operation_data['parameters']['alert_indexed']:
            print("Check alert indexed")
            check_vuln_alert_indexer(host_manager, operation_data['vulnerability_data'])

        if operation_data['parameters']['api']:
            print("Check vuln in api response")
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
    indexer_alerts = get_indexer_values(host_manager)

    pass

def check_vuln_alert_api(host_manager: HostManager, vulnerability_data: Dict[str, Dict]):
    """
    Check vulnerability alerts via API for a host.

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        vulnerability_data (dict): Dictionary containing vulnerability data.

    ToDo:
        Implement the functionality.
    """

    api_vulns = get_agents_vulnerabilities(host_manager)
    not_found_vuln = []



    for agent in host_manager.get_group_hosts('agent'):
        print("\n\n---------------------------------")
        print(f"Agent {agent}")

        agent_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        agent_arch_name = host_manager.get_host_variables(agent)['architecture']
        vulnerability_data_agent = vulnerability_data[agent_os_name][agent_arch_name]
        current_vulns_agent = api_vulns[agent]
        print(f"Vuln of agent {agent}: {vulnerability_data_agent}")
        for vulnerability in vulnerability_data_agent:
            print(f"Searching for {agent} and {vulnerability['CVE']}")
            expected_vuln = {
                'status': 'VALID',
                'cve': vulnerability['CVE']
            }
            found = False
            for current_vulnerability in current_vulns_agent:
                if all(current_vulnerability[key] == value for key, value in expected_vuln.items()):
                    found = True
                    print(f"Found {current_vulnerability}")

            if not found:
                not_found_vuln.append({
                    'agent': agent,
                    'cve': vulnerability['CVE']
                })
        print("\n\n---------------------------------")


    print(f"No found {not_found_vuln}")
    assert len(not_found_vuln) == 0

    # Check alerts





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
