"""
Logs management module for remote hosts.
---------------------------------------

Description:
    This module provides functions for truncating logs and alerts for Wazuh agents and managers.

Functions:
    - truncate_agents_logs: Truncate logs for Wazuh agents.
    - truncate_managers_logs: Truncate logs for Wazuh managers.
    - truncate_logs: Truncate logs for both Wazuh agents and managers.
    - truncate_alerts: Truncate Wazuh alerts.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.tools.system import HostManager 


def truncate_agents_logs(host_manager: HostManager) -> None:
    """
    Truncate logs for Wazuh agents.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
    """
    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os_name']
        host_manager.truncate_file(agent, logs_filepath_os[host_os_name])

def truncate_managers_logs(host_manager: HostManager) -> None:
    """
    Truncate logs for Wazuh managers.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
    """
    for manager in host_manager.get_group_hosts('manager'):
        host_os_name = host_manager.get_host_variables(manager)['os_name']
        host_manager.truncate_file(manager, logs_filepath_os[host_os_name])

def truncate_logs(host_manager: HostManager) -> None:
    """
    Truncate logs for both Wazuh agents and managers.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
    """
    truncate_managers_logs(host_manager)
    truncate_agents_logs(host_manager)

def truncate_alerts(host_manager: HostManager) -> None:
    """
    Truncate Wazuh alerts.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
    """
    for manager in host_manager.get_group_hosts('manager'):
        host_manager.truncate_file(manager, '/var/ossec/logs/alerts/alerts.json')

