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
from concurrent.futures import ThreadPoolExecutor

from typing import Any, Dict, List
from wazuh_testing.end_to_end.vulnerability_detector import (Vulnerability,
                                                             get_vulnerabilities_from_alerts_by_agent,
                                                             get_vulnerabilities_from_states_by_agent,
                                                             load_packages_metadata)
from wazuh_testing.tools.system import HostManager


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


def get_expected_vulnerabilities_for_package(
    host_manager: HostManager, host: str, package_id: str
) -> list:

    package_data = load_packages_metadata()[package_id]
    vulnerabilities_list = []

    host_os_arch = host_manager.get_host_variables(host)["architecture"]
    system = host_manager.get_host_variables(host)["os_name"]
    use_npm = package_data.get('use_npm', False)

    architecture = ''
    if use_npm:
        architecture = ''
    else:
        if host_os_arch == "amd64":
            architecture = "x86_64"
        elif host_os_arch == "arm64v8":
            architecture = "arm64"
        else:
            architecture = host_os_arch

    if system == "linux":
        system = host_manager.get_host_variables(host)["os"].split("_")[0]

    for cve in package_data["CVE"]:
        vulnerability = Vulnerability(
            cve,
            package_data["package_name"],
            package_data["package_version"],
            architecture,
        )
        vulnerabilities_list.append(vulnerability)

    vulnerabilities = sorted(
        vulnerabilities_list,
        key=lambda x: (x.cve, x.package_name, x.package_version, x.architecture),
    )

    return vulnerabilities


def filter_vulnerabilities_by_packages(host_manager: HostManager,
                                       vulnerabilities: Dict, packages_data: List) -> Dict:
    filtered_vulnerabilities = {}
    for host in vulnerabilities.keys():
        packages_to_filter = set()
        filtered_vulnerabilities[host] = []
        host_os_name = host_manager.get_host_variables(host)["os"].split("_")[0]
        host_os_arch = host_manager.get_host_variables(host)["architecture"]

        for package_data in packages_data:
            package_id = package_data[host_os_name][host_os_arch]
            data = load_packages_metadata()[package_id]
            package_name = data["package_name"]
            packages_to_filter.add(package_name)

        for vulnerability in vulnerabilities[host]:
            if vulnerability.package_name in list(packages_to_filter):
                filtered_vulnerabilities[host].append(vulnerability)

    return filtered_vulnerabilities


def get_expected_vulnerabilities_by_agent(
    host_manager: HostManager, agents_list: List, packages_data: Dict
) -> Dict:
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
        host_os_name = host_manager.get_host_variables(agent)["os"].split("_")[0]
        host_os_arch = host_manager.get_host_variables(agent)["architecture"]

        expected_vulnerabilities_by_agent[agent] = []
        package_id = packages_data[host_os_name][host_os_arch]
        expected_vulnerabilities = get_expected_vulnerabilities_for_package(
            host_manager, agent, package_id
        )
        expected_vulnerabilities_by_agent[agent] = expected_vulnerabilities

    return expected_vulnerabilities_by_agent


def get_package_url_for_host(
    host: str, package_data: Dict[str, Any], host_manager: HostManager
) -> str:

    host_os_name = host_manager.get_host_variables(host)["os"].split("_")[0]
    host_os_arch = host_manager.get_host_variables(host)["architecture"]
    system = host_manager.get_host_variables(host)["os_name"]

    if system == "linux":
        system = host_manager.get_host_variables(host)["os"].split("_")[0]

    try:
        package_id = package_data[host_os_name][host_os_arch]
        package_data = load_packages_metadata()[package_id]
        package_url = package_data["urls"][host_os_name][host_os_arch]

        return package_url
    except KeyError:
        raise ValueError(
            f"Package for {host_os_name} and {host_os_arch} not found. Maybe {host} OS is not supported."
        )


def get_package_npm(
    host: str, package_data: Dict[str, Any], host_manager: HostManager
) -> bool:
    host_os_name = host_manager.get_host_variables(host)["os"].split("_")[0]
    host_os_arch = host_manager.get_host_variables(host)["architecture"]
    system = host_manager.get_host_variables(host)["os_name"]

    if system == "linux":
        system = host_manager.get_host_variables(host)["os"].split("_")[0]

    install_package_data = package_data

    package_id = install_package_data[host_os_name][host_os_arch]
    package_data = load_packages_metadata()[package_id]
    package_npm = package_data.get("use_npm", False)

    return package_npm


def get_package_uninstallation_name(
    host: str,
    package_id: str,
    host_manager: HostManager,
    operation_data: Dict[str, Any],
) -> str:
    host_os_name = host_manager.get_host_variables(host)["os"].split("_")[0]
    host_os_arch = host_manager.get_host_variables(host)["architecture"]
    system = host_manager.get_host_variables(host)["os_name"]

    if system == "linux":
        system = host_manager.get_host_variables(host)["os"].split("_")[0]

    install_package_data = operation_data["package"]
    try:
        package_id = install_package_data[host_os_name][host_os_arch]
        package_data = load_packages_metadata()[package_id]

        if system == 'windows':
            package_uninstall_name = package_data['product_id']
        else:
            package_uninstall_name = package_data["uninstall_name"]

        return package_uninstall_name
    except KeyError:
        raise ValueError(
            f"Package for {host_os_name} and {host_os_arch} not found uninstall name."
        )


def get_package_system(host: str, host_manager: HostManager) -> str:
    system = host_manager.get_host_variables(host)["os_name"]
    if system == "linux":
        system = host_manager.get_host_variables(host)["os"].split("_")[0]

    return system


def get_vulnerability_alerts(host_manager: HostManager, agent_list, packages_data: List,
                             greater_than_timestamp: str = "") -> Dict:
    alerts = get_vulnerabilities_from_alerts_by_agent(
        host_manager, agent_list, greater_than_timestamp=greater_than_timestamp
    )
    alerts_vulnerabilities = filter_vulnerabilities_by_packages(
        host_manager, alerts["affected"], packages_data
    )
    alerts_vulnerabilities_mitigated = filter_vulnerabilities_by_packages(
        host_manager, alerts["mitigated"], packages_data
    )

    return {
        "affected": alerts_vulnerabilities,
        "mitigated": alerts_vulnerabilities_mitigated,
    }


def get_vulnerabilities_index(host_manager: HostManager, agent_list, packages_data: List[Dict],
                              greater_than_timestamp: str = "") -> Dict:
    vulnerabilities = get_vulnerabilities_from_states_by_agent(host_manager, agent_list,
                                                               greater_than_timestamp=greater_than_timestamp)
    package_vulnerabilities = filter_vulnerabilities_by_packages(host_manager, vulnerabilities, packages_data)

    return package_vulnerabilities


def get_expected_alerts(
    host_manager: HostManager, agent_list, operation: str, packages_data: Dict
) -> Dict:
    expected_alerts_vulnerabilities = {"affected": {}, "mitigated": {}}

    if operation == "update_package":
        expected_alerts_vulnerabilities["mitigated"] = (
            get_expected_vulnerabilities_by_agent(
                host_manager, agent_list, packages_data["from"]
            )
        )
        expected_alerts_vulnerabilities["affected"] = (
            get_expected_vulnerabilities_by_agent(
                host_manager, agent_list, packages_data["to"]
            )
        )
    elif operation == "remove_package":
        expected_alerts_vulnerabilities["mitigated"] = (
            get_expected_vulnerabilities_by_agent(
                host_manager, agent_list, packages_data
            )
        )
    elif operation == "install_package":
        expected_alerts_vulnerabilities["affected"] = (
            get_expected_vulnerabilities_by_agent(
                host_manager, agent_list, packages_data
            )
        )

    return expected_alerts_vulnerabilities


def get_expected_index(host_manager: HostManager, agent_list, operation: str, packages_data: Dict) -> Dict:
    expected_index = {}
    if operation == "update_package":
        expected_index = get_expected_vulnerabilities_by_agent(host_manager, agent_list, packages_data["to"])
    elif operation == "install_package":
        expected_index = get_expected_vulnerabilities_by_agent(host_manager, agent_list, packages_data)

    return expected_index


def install_package(
    host: str, operation_data: Dict[str, Any], host_manager: HostManager
) -> bool:
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    package = operation_data['package']
    if 'to' in operation_data['package'].keys():
        package = package['to']

    result = True
    logging.info(f"Installing package on {host}")
    package_url = get_package_url_for_host(
        host, package, host_manager
    )
    package_system = get_package_system(host, host_manager)
    npm_package = get_package_npm(host, package, host_manager)

    try:
        if npm_package:
            host_manager.install_npm_package(host, package_url, package_system)
        else:
            host_manager.install_package(host, package_url, package_system)
    except Exception as e:
        logging.error(f"Error installing package on {host}: {e}")
        result = False

    return result


def remove_package(host: str, operation_data: Dict[str, Any], host_manager: HostManager) -> bool:
    """
    Install a package on the specified host.

    Args:
        host (str): The target host on which to perform the operation.
        operation_data (dict): Dictionary containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.

    Raises:
        ValueError: If the specified operation is not recognized.
    """
    result = True
    logging.info(f"Removing package on {host}")
    package_system = get_package_system(host, host_manager)

    try:
        package_uninstall_name = None
        custom_uninstall_playbook = None
        package_data = operation_data['package']

        npm_package = get_package_npm(host, package_data, host_manager)
        try:
            package_uninstall_name = get_package_uninstallation_name(
                host, package_data, host_manager, operation_data
            )
        except ValueError:
            logging.info(
                f"No uninstall name found for {operation_data['package']}. Searching for custom playbook"
            )
            custom_uninstall_playbook = (
                package_data["uninstall_playbook"]
                if "uninstall_playbook" in package_data
                else None
            )

        if npm_package:
            host_manager.remove_npm_package(
                host, package_system, package_uninstall_name, custom_uninstall_playbook
            )
        else:
            host_manager.remove_package(
                host, package_system, package_uninstall_name, custom_uninstall_playbook
            )

    except Exception as e:
        logging.error(f"Error removing package on {host}: {e}")
        result = False

    return result


def update_package(
    host: str, operation_data: Dict[str, Any], host_manager: HostManager
) -> bool:
    result = True
    logging.info(f"Installing package on {host}")
    package_url = get_package_url_for_host(
        host, operation_data["package"]["to"], host_manager
    )
    package_system = get_package_system(host, host_manager)
    npm_package = get_package_npm(host, operation_data['package']['to'], host_manager)

    try:
        if npm_package:
            host_manager.install_npm_package(host, package_url, package_system)
        else:
            host_manager.install_package(host, package_url, package_system)
    except Exception as e:
        logging.error(f"Error installing package on {host}: {e}")
        result = False

    return result


def launch_remote_operation(
    host: str, operation_data: Dict[str, Dict], host_manager: HostManager
):
    operation = operation_data["operation"]
    if operation in globals():
        operation_result = globals()[operation](host, operation_data, host_manager)
        logging.info(f"Operation result: {operation_result}")
        return operation_result
    else:
        raise ValueError(f"Operation {operation} not recognized")


def filter_hosts_by_os(host_manager: HostManager, os_list: List[str]) -> List[str]:
    agents = host_manager.get_group_hosts('agent')
    agents_target_os = []
    for agent in agents:
        system = host_manager.get_host_variables(agent)["os_name"]

        if system == "linux":
            system = host_manager.get_host_variables(agent)["os"].split("_")[0]

        if system in os_list:
            agents_target_os.append(agent)

    return agents_target_os


def launch_parallel_operations(task: Dict[str, List], host_manager: HostManager,
                               target_to_ignore: List[str] = None):
    """
    Launch parallel remote operations on multiple hosts.

    Args:
        operation (list): List of dictionaries containing operation details.
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
    """

    hosts_to_ignore = target_to_ignore if target_to_ignore else []
    target = "agent"
    results = {}
    lock = threading.Lock()

    def launch_and_store_result(args):
        host, task, manager = args
        result = launch_remote_operation(host, task, manager)
        with lock:
            results[host] = result

    with ThreadPoolExecutor() as executor:
        # Submit tasks asynchronously
        hosts_target = host_manager.get_group_hosts(target)

        futures = []

        # Calculate the hosts to ignore based on previous operations results
        if hosts_to_ignore:
            hosts_target = [
                host for host in hosts_target if host not in hosts_to_ignore
            ]

        logging.info(f"Launching operation {task['operation']} on {hosts_target}")

        for host in hosts_target:
            futures.append(
                executor.submit(launch_and_store_result, (host, task, host_manager))
            )

        # Wait for all tasks to complete
        for future in futures:
            future.result()

    logging.info("Results in parallel operations: {}".format(results))

    return results
