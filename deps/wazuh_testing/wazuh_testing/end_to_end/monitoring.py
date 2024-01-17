"""
Monitoring remote host files module.
------------------------------------

Description:
    This module provides functions for monitoring events, files, and alerts in a Wazuh environment.

Functions:
    - monitoring_events_multihost: Monitor events on multiple hosts concurrently.
    - generate_monitoring_logs_all_agent: Generate monitoring data for logs on all agent hosts.
    - generate_monitoring_logs_manager: Generate monitoring data for logs on a specific manager host.
    - generate_monitoring_alerts_all_agent: Generate monitoring data for alerts on all agent hosts.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import re
from time import sleep
from typing import Dict, List
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor, as_completed

from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.tools.system import HostManager


def monitoring_events_multihost(host_manager: HostManager, monitoring_data: Dict, ignore_error=False) -> Dict:
    """
    Monitor events on multiple hosts concurrently.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        monitoring_data: A dictionary containing monitoring data for each host.
    """
    def monitoring_event(host_manager: HostManager, host: str, monitoring_elements: List[Dict], scan_interval: int = 20,
                         ignore_error=False):
        """
        Monitor the specified elements on a host.

        Args:
            host_manager (HostManager): Host Manager to handle the environment
            host (str): The target host.
            monitoring_elements(List): A list of dictionaries containing regex, timeout, and file.

        Raises:
            TimeoutError: If no match is found within the specified timeout.
        """
        elements_not_found = []
        elements_found = []

        for element in monitoring_elements:
            regex, timeout, monitoring_file, n_iterations = element['regex'], element['timeout'], element['file'], \
                                                            element['n_iterations']
            current_timeout = 0
            regex_match = None

            while current_timeout < timeout:
                file_content = host_manager.get_file_content(host, monitoring_file)

                match_regex = re.findall(regex, file_content)
                if match_regex and len(list(match_regex)) >= n_iterations:
                    elements_found = list(match_regex)
                    regex_match = True
                    break

                sleep(scan_interval)

                current_timeout += 5

            if not regex_match:
                elements_not_found.append(element)
                if not ignore_error:
                    raise TimeoutError(f"Element not found: {element}")

        monitoring_result = {}

        if host not in monitoring_result:
            monitoring_result[host] = {}

        monitoring_result[host]['not_found'] = elements_not_found

        monitoring_result[host]['found'] = elements_found

        return monitoring_result

    with ThreadPoolExecutor() as executor:
        futures = []
        for host, data in monitoring_data.items():
            futures.append(executor.submit(monitoring_event, host_manager, host, data, ignore_error))

        results = {}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.update(result)
            except Exception as e:
                print(f"An error occurred: {e}")

        return results


def generate_monitoring_logs(host_manager: HostManager, regex_list: list, timeout_list: list, hosts: list,
                             n_iterations=1) -> dict:
    """
    Generate monitoring data for logs on all agent hosts.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        regex_list: A list of regular expressions for monitoring.
        timeout_list: A list of timeout values for monitoring.

    Returns:
        dict: Monitoring data for logs on all agent hosts.
    """
    monitoring_data = {}
    for agent in hosts:
        monitoring_data[agent] = []
        for index, regex_index in enumerate(regex_list):
            os_name = host_manager.get_host_variables(agent)['os_name']
            monitoring_data[agent].append({
                'regex': regex_index,
                'file': logs_filepath_os[os_name],
                'timeout': timeout_list[index],
                'n_iterations': n_iterations
            })
    return monitoring_data


def generate_monitoring_logs_manager(host_manager: HostManager, manager: str, regex: str, timeout: int,
                                     n_iterations: int = 1) -> dict:
    """
    Generate monitoring data for logs on a specific manager host.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        manager: The target manager host.
        regex: The regular expression for monitoring.
        timeout: The timeout value for monitoring.

    Returns:
        dict: Monitoring data for logs on the specified manager host.
    """
    monitoring_data = {}
    os_name = host_manager.get_host_variables(manager)['os_name']
    monitoring_data[manager] = [{
        'regex': regex,
        'file': logs_filepath_os[os_name],
        'timeout': timeout,
        'n_iterations': n_iterations
    }]

    return monitoring_data


def generate_monitoring_alerts_all_agent(host_manager: HostManager, events_metadata: dict) -> dict:
    """
    Generate monitoring data for alerts on all agent hosts.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        events_metadata: Metadata containing information about events.

    Returns:
        dict: Monitoring data for alerts on all agent hosts.
    """
    monitoring_data = {}

    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        metadata_agent = events_metadata[host_os_name]

        if not host_manager.get_host_variables(agent)['manager'] in monitoring_data:
            monitoring_data[host_manager.get_host_variables(agent)['manager']] = []

        for event in metadata_agent[host_manager.get_host_variables(agent)['arch']]:
            event['parameters']['HOST_NAME'] = agent
            monitoring_element = {
                'regex': get_event_regex(event),
                'file': '/var/ossec/logs/alerts/alerts.json',
                'timeout': 120,
                'n_iterations': 1
            }
            if 'parameters' in metadata_agent:
                monitoring_element['parameters'] = metadata_agent['parameters']

            monitoring_data[host_manager.get_host_variables(agent)['manager']].append(monitoring_element)

    return monitoring_data
