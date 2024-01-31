"""
Monitoring remote host files module.
------------------------------------

Description:
    This module provides functions for monitoring events, files, and alerts in a Wazuh environment.

Functions:
    - monitoring_events_multihost: Monitor events on multiple hosts concurrently.
    - generate_monitoring_logs: Generate monitoring data for logs on all agent hosts.
    - generate_monitoring_logs_manager: Generate monitoring data for logs on a specific manager host.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import re
import logging
from time import sleep
from datetime import datetime
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.tools.system import HostManager


def monitoring_events_multihost(host_manager: HostManager, monitoring_data: Dict, ignore_error: bool = False) -> Dict:
    """
    Monitor events on multiple hosts concurrently.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        monitoring_data: A dictionary containing monitoring data for each host.
        ignore_error: If True, ignore errors and continue monitoring.
    """
    def monitoring_event(host_manager: HostManager, host: str, monitoring_elements: List[Dict], scan_interval: int = 20,
                         ignore_error: bool = False) -> Dict:
        """
        Monitor the specified elements on a host.

        Args:
            host_manager (HostManager): Host Manager to handle the environment
            host (str): The target host.
            monitoring_elements(List): A list of dictionaries containing regex, timeout, and file.
            ignore_error: If True, ignore errors and continue monitoring.

        Raises:
            TimeoutError: If no match is found within the specified timeout.
        """
        def filter_events_by_timestamp(match_events: List) -> List:
            """
            Filter events by timestamp.

            Args:
                match_events (List): A list of events.

            Returns:
                List: A list of events that fit the timestamp.
            """
            match_that_fit_timestamp = []
            for match in match_events:
                if len(match.groups()) > 1:
                    timestamp_str = match.groups()[0]
                    timestamp_format = "%Y/%m/%d %H:%M:%S"
                    timestamp_datetime = datetime.strptime(timestamp_str, timestamp_format)
                    if timestamp_datetime >= greater_than_timestamp:
                        match_that_fit_timestamp.append(match)

            return match_that_fit_timestamp

        elements_not_found = []
        elements_found = []

        for element in monitoring_elements:
            regex, timeout, monitoring_file, n_iterations, greater_than_timestamp = element['regex'], \
                                                            element['timeout'], element['file'], \
                                                            element['n_iterations'], \
                                                            element.get('greater_than_timestamp', None)
            current_timeout = 0
            regex_match = None

            while current_timeout < timeout:
                file_content = host_manager.get_file_content(host, monitoring_file)

                match_regex = re.findall(regex, file_content)

                if greater_than_timestamp:
                    match_that_fit_timestamp = filter_events_by_timestamp(match_regex)
                else:
                    match_that_fit_timestamp = list(match_regex)

                if match_that_fit_timestamp and len(list(match_that_fit_timestamp)) >= n_iterations:
                    elements_found = list(match_that_fit_timestamp)
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

        monitoring_result = {host: {'not_found': elements_not_found, 'found': elements_found}}

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
                logging.error(f"An error occurred: {e}")

        return results


def generate_monitoring_logs(host_manager: HostManager, regex_list: List[str], timeout_list: List[str],
                             hosts: List[str], n_iterations=1, greater_than_timestamp: str = '') -> Dict:
    """
    Generate monitoring data for logs on all agent hosts.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        regex_list: A list of regular expressions for monitoring.
        timeout_list: A list of timeout values for monitoring.
        hosts: A list of target hosts.
        n_iterations: The number of iterations to find the regex. Defaults to 1.
        greater_than_timestamp: The timestamp to filter the results. Defaults to None.

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
                'n_iterations': n_iterations,
                'greater_than_timestamp': greater_than_timestamp
            })
    return monitoring_data


def generate_monitoring_logs_manager(host_manager: HostManager, manager: str, regex: str, timeout: int,
                                     n_iterations: int = 1, greater_than_timestamp: str = '') -> Dict:
    """
    Generate monitoring data for logs on a specific manager host.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        manager: The target manager host.
        regex: The regular expression for monitoring.
        timeout: The timeout value for monitoring.
        greater_than_timestamp: The timestamp to filter the results. Defaults to None.

    Returns:
        dict: Monitoring data for logs on the specified manager host.
    """
    monitoring_data = {}
    os_name = host_manager.get_host_variables(manager)['os_name']
    monitoring_data[manager] = [{
        'regex': regex,
        'file': logs_filepath_os[os_name],
        'timeout': timeout,
        'n_iterations': n_iterations,
        'greater_than_timestamp': greater_than_timestamp
    }]

    return monitoring_data
