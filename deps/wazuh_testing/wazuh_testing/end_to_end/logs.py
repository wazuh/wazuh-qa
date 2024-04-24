"""
Logs management module for remote hosts.
---------------------------------------

Description:
    This module provides functions for truncating logs and alerts for Wazuh agents and managers.

Functions:
    - truncate_remote_host_group_files: Truncate the specified files in all the host of a group
    - get_hosts_logs: Get the logs from the specified host group


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import re
from datetime import datetime
from typing import Dict, List

from wazuh_testing import ALERTS_JSON_PATH
from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.tools.system import HostManager


def truncate_remote_host_group_files(host_manager: HostManager, host_group: str,
                                     file_to_truncate: str = 'logs') -> None:
    """
    Truncate log or alert files on remote hosts in a specified host group.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class for managing remote hosts.
    - host_group (str): The name of the host group where the files will be truncated.
    - file_to_truncate (str, optional): The type of file to truncate. Default is 'logs'.
      Possible values are 'logs' for log files or 'alerts' for alert files.
    """
    for host in host_manager.get_group_hosts(host_group):
        if file_to_truncate == 'logs':
            host_os_name = host_manager.get_host_variables(host)['os_name']
            log_file_path = logs_filepath_os[host_os_name]
        elif file_to_truncate == 'alerts':
            log_file_path = ALERTS_JSON_PATH
        else:
            log_file_path = file_to_truncate

        host_manager.truncate_file(host, log_file_path)


def get_hosts_logs(host_manager: HostManager, host_group: str = 'all') -> Dict[str, str]:
    """
    Get the logs from the specified host group.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class for managing remote hosts.
    - host_group (str, optional): The name of the host group where the files will be truncated.
      Default is 'all'.

    Returns:
    - host_logs (Dict[str, str]): Dictionary containing the logs from the ossec.log file of each host
    """
    host_logs = {}
    for host in host_manager.get_group_hosts(host_group):
        host_os_name = host_manager.get_host_variables(host)['os_name']
        host_logs[host] = host_manager.get_file_content(host, logs_filepath_os[host_os_name])

    return host_logs


def check_errors_in_environment(host_manager: HostManager, greater_than_timestamp: str = '',
                                expected_errors: List[str] = None) -> dict:
    """Check if there are errors in the environment

    Args:
        host_manager (HostManager): An instance of the HostManager class.
        greater_than_timestamp (str): Timestamp to filter the logs
        expected_errors (List): List of expected errors. Default None

    Returns:
        dict: Errors found in the environment
    """

    error_level_to_search = ['ERROR', 'CRITICAL', 'WARNING']
    expected_errors = expected_errors or []

    environment_logs = get_hosts_logs(host_manager)
    environment_level_logs = {}

    for host, environment_log in environment_logs.items():
        environment_level_logs[host] = {}
        for level in error_level_to_search:
            environment_level_logs[host][level] = []
            regex = re.compile(fr'((\d{{4}}\/\d{{2}}\/\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}) (.+): ({level}):(.*))')

            matches = regex.findall(environment_log)

            for match in matches:
                if not any(re.search(error, match[0]) for error in expected_errors):
                    if greater_than_timestamp:
                        date_format = "%Y/%m/%d %H:%M:%S"
                        default_tiemstamp_format = "%Y-%m-%dT%H:%M:%S"

                        date_filter_format = datetime.strptime(greater_than_timestamp, default_tiemstamp_format)
                        log_date = datetime.strptime(match[1], date_format)

                        if log_date > date_filter_format:
                            environment_level_logs[host][level].append(match[0])
                    else:
                        environment_level_logs[host][level].append(match[0])

    return environment_level_logs


def get_hosts_alerts(host_manager: HostManager) -> Dict[str, str]:
    """
    Get the alerts in the alert.json file from the specified host group.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class for managing remote hosts.

    Returns:
    - host_alerts (Dict[str, str]): Dictionary containing the alerts from the alert.json file of each manager
    """
    host_alerts = {}
    for host in host_manager.get_group_hosts("manager"):
        host_alerts[host] = host_manager.get_file_content(host, ALERTS_JSON_PATH)

    return host_alerts
