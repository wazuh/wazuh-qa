"""
Module Name: logs

Description:
    This module provides functions for truncating logs and alerts for Wazuh agents and managers.

Functions:
    1. truncate_agents_logs(host_manager: HostManager) -> None:
        Truncate logs for Wazuh agents.

        Args:
            host_manager: An instance of the HostManager class containing information about hosts.

    2. truncate_managers_logs(host_manager: HostManager) -> None:
        Truncate logs for Wazuh managers.

        Args:
            host_manager: An instance of the HostManager class containing information about hosts.

    3. truncate_logs(host_manager: HostManager) -> None:
        Truncate logs for both Wazuh agents and managers.

        Args:
            host_manager: An instance of the HostManager class containing information about hosts.

    4. truncate_alerts(host_manager: HostManager) -> None:
        Truncate Wazuh alerts.

        Args:
            host_manager: An instance of the HostManager class containing information about hosts.

Module Usage:
    This module can be used to truncate logs and alerts for Wazuh agents and managers.
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

