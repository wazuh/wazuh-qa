"""
Monitoring remote host files module.
------------------------------------

Description:
    This module provides functions for monitoring events, files, and alerts in a Wazuh environment.

Functions:
    - monitoring_events_multihost: Monitor events on multiple hosts concurrently.
    - generate_monitoring_logs: Generate monitoring data for logs on all agent hosts.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from time import sleep
from typing import Dict, List

from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.tools.system import HostManager

DEFAULT_SCAN_INTERVAL = 5


def monitoring_events_multihost(host_manager: HostManager, monitoring_data: Dict, ignore_timeout_error: bool = True,
                                scan_interval: int = DEFAULT_SCAN_INTERVAL) -> Dict:
    """
    Monitor events on multiple hosts concurrently.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        monitoring_data: A dictionary containing monitoring data for each host.
        ignore_timeout_error: If True, ignore TimeoutError and return the result.

    Returns:
        dict: A dictionary containing the monitoring results.

    Example of monitoring_data:
        {
           "manager1":[
              {
                 "regex":"INFO: Action for 'vulnerability_feed_manager' finished",
                 "file":"/var/ossec/logs/ossec.log",
                 "timeout":1000,
                 "n_iterations":1,
                 "greater_than_timestamp":""
              }
           ]
        }
    Example of monitoring_result:
        {
           "manager1":{
              "not_found":[
              ],
              "found":[
                 "INFO: Action for 'vulnerability_feed_manager' finished"
              ]
           }
        }
    """
    def monitoring_event(host_manager: HostManager, host: str, monitoring_elements: List[Dict],
                         ignore_timeout_error: bool = True,
                         scan_interval: int = DEFAULT_SCAN_INTERVAL) -> Dict:
        """
        Monitor the specified elements on a host.

        Args:
            host_manager (HostManager): Host Manager to handle the environment
            host (str): The target host.
            monitoring_elements(List): A list of dictionaries containing regex, timeout, and file.
            ignore_timeout_error: If True, ignore TimeoutError and return the result.

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
                if match.__class__ == tuple:
                    timestamp_str = match[0]
                else:
                    timestamp_str = match

                timestamp_format = "%Y/%m/%d %H:%M:%S"
                timestamp_format_parameter = "%Y-%m-%dT%H:%M:%S"

                try:
                    timestamp_datetime = datetime.strptime(timestamp_str, timestamp_format)
                    greater_than_timestamp_formatted = datetime.strptime(greater_than_timestamp,
                                                                         timestamp_format_parameter)
                except ValueError:
                    raise ValueError(f"Timestamp format not supported: {timestamp_str}."
                                     'Do the regex includes the timestamp?')

                if timestamp_datetime >= greater_than_timestamp_formatted:
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
            regex_match = False

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

                current_timeout = current_timeout + scan_interval

            if not regex_match:
                elements_not_found.append(element)
                if not ignore_timeout_error:
                    raise TimeoutError(f"Element not found: {element}")

        monitoring_result = {}

        if host not in monitoring_result:
            monitoring_result[host] = {}

        monitoring_result = {host: {'not_found': elements_not_found, 'found': elements_found}}

        return monitoring_result

    logging.info(f"Monitoring the following elements: {monitoring_data}")

    with ThreadPoolExecutor() as executor:
        futures = []
        for host, data in monitoring_data.items():
            futures.append(executor.submit(monitoring_event, host_manager, host, data, ignore_timeout_error,
                                           scan_interval))

        results = {}
        for future in as_completed(futures):
            result = future.result()
            results.update(result)

        logging.info(f"Monitoring results: {results}")

        return results


def generate_monitoring_logs(host_manager: HostManager, regex_list: List[str], timeout_list: List[int],
                             hosts: List[str], n_iterations=1, greater_than_timestamp: str = '') -> Dict:
    """
    Generate monitoring data for logs on all provided hosts.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        regex_list: A list of regular expressions for monitoring.
        timeout_list: A list of timeout values for monitoring.
        hosts: A list of target hosts.
        n_iterations: The number of iterations to find the regex. Defaults to 1.
        greater_than_timestamp: The timestamp to filter the results. Defaults to None.

    Returns:
        dict: Monitoring data for logs on all agent hosts.

    Example of monitoring_data:
        {
           "agent1":[
              {
                 "regex":["INFO: Action for 'vulnerability_feed_manager' finished"],
                 "file":"/var/ossec/logs/ossec.log",
                 "timeout":1000,
                 "n_iterations":1,
                 "greater_than_timestamp":""
              }
           ]
        }

    """
    monitoring_data = {}

    for host in hosts:
        monitoring_data[host] = []
        for index, regex_index in enumerate(regex_list):
            os_name = host_manager.get_host_variables(host)['os_name']
            monitoring_data[host].append({
                'regex': regex_index,
                'file': logs_filepath_os[os_name],
                'timeout': timeout_list[index],
                'n_iterations': n_iterations,
                'greater_than_timestamp': greater_than_timestamp
            })

    return monitoring_data


def monitoring_syscollector_scan_agents(host_manager: HostManager, timeout: int,
                                        greater_than_timestamp: str = '') -> list:
    """Monitor syscollector scan on agents.

    Args:
        host_manager (HostManager): An instance of the HostManager class.
        timeout (int): The timeout value for monitoring.
        greater_than_timestamp_formatted (str): Timestamp to filter agents logs. Default ''

    Returns:
        list: A list of agents that were not scanned.
    """
    agents_not_scanned = []

    logging.info("Monitoring syscollector first scan")
    list_hosts = host_manager.get_group_hosts('agent')
    monitoring_data = generate_monitoring_logs(host_manager,
                                               [get_event_regex({'event': 'syscollector_scan_start'}),
                                                get_event_regex({'event': 'syscollector_scan_end'})],
                                               [timeout, timeout],
                                               list_hosts, greater_than_timestamp=greater_than_timestamp)
    monitoring_results = monitoring_events_multihost(host_manager, monitoring_data)

    logging.info(f"Value of monitoring results is: {monitoring_results}")

    for agent in monitoring_results:
        if monitoring_results[agent]['not_found']:
            agents_not_scanned.append(agent)

    return agents_not_scanned
