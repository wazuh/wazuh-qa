"""
Logs management module for remote hosts.
---------------------------------------

Description:
    This module provides functions for truncating logs and alerts for Wazuh agents and managers.

Functions:
    - truncate_remote_host_group_files: Truncate the specified files in all the host of a group


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from wazuh_testing import ALERTS_JSON_PATH
from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.tools.system import HostManager


def truncate_remote_host_group_files(host_manager: HostManager, host_group: str,
                                     file_to_truncate: str='logs'):
    """
    Truncate log or alert files on remote hosts in a specified host group.

    Parameters:
    - host_manager (HostManager): An instance of the HostManager class for managing remote hosts.
    - host_group (str): The name of the host group where the files will be truncated.
    - file_to_truncate (str, optional): The type of file to truncate. Default is 'logs'.
      Possible values are 'logs' for log files or 'alerts' for alert files.
    """
    for host in host_manager.get_group_hosts(host_group):
        log_file_path = None
        if file_to_truncate == 'logs':
            host_os_name = host_manager.get_host_variables(host)['os_name']
            log_file_path = logs_filepath_os[host_os_name]
        elif file_to_truncate == 'alerts':
            log_file_path = ALERTS_JSON_PATH

        host_manager.truncate_file(host, log_file_path)


def get_hosts_logs(host_manager: HostManager, host_group: str = 'all') -> dict:
    host_logs = {}
    for host in host_manager.get_group_hosts(host_group):
        host_os_name = host_manager.get_host_variables(host)['os_name']
        host_logs[host] = host_manager.get_file_content(host, logs_filepath_os[host_os_name])

    return host_logs
