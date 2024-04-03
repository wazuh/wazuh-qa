"""
Module to handle waiters for the end-to-end tests.
-----------------------------------------------------

This module provides functions for waiting until vulnerability data is updated for all manager hosts and until
vulnerability scans for all agents are finished.

Functions:
    - wait_until_vd_is_updated: Wait until the vulnerability data is updated for all manager hosts.
    - wait_until_vuln_scan_agents_finished: Wait until vulnerability scans for all agents are finished.
    - wait_syscollector_and_vuln_scan: Wait until syscollector and vulnerability scans are finished for a specific host.

Constants:
    - VD_FEED_UPDATE_TIMEOUT: Time in seconds to wait until the vulnerability data is updated for all manager hosts.
    - VD_INITIAL_SCAN_PER_AGENT_TIMEOUT: Time in seconds to wait until vulnerability scans for each agent is finished.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import time
import logging
from typing import Dict

from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs, monitoring_events_multihost
from wazuh_testing.end_to_end.wazuh_api import get_agents_id
from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.end_to_end.logs import truncate_remote_host_group_files
from wazuh_testing.tools.system import HostManager
from wazuh_testing.modules.syscollector import TIMEOUT_SYSCOLLECTOR_SHORT_SCAN


VD_FEED_UPDATE_TIMEOUT = 600
VD_INITIAL_SCAN_PER_AGENT_TIMEOUT = 15


def wait_until_vd_is_updated(host_manager: HostManager) -> None:
    """
    Wait until the vulnerability data is updated for all manager hosts.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """

    monitoring_data = generate_monitoring_logs(host_manager, ["INFO: Vulnerability scanner module started"],
                                               [VD_FEED_UPDATE_TIMEOUT], host_manager.get_group_hosts('manager'))
    monitoring_events_multihost(host_manager, monitoring_data)


def wait_until_vuln_scan_agents_finished(host_manager: HostManager) -> None:
    """
    Wait until vulnerability scans for all agents are finished.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """
    final_timeout = VD_INITIAL_SCAN_PER_AGENT_TIMEOUT * len(get_agents_id(host_manager))
    time.sleep(final_timeout)


def wait_syscollector_and_vuln_scan(host_manager: HostManager, host: str,  operation_data: Dict,
                                    current_datetime: str = '') -> None:
    """
    Wait until syscollector and vulnerability scans are finished for a specific host.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
        host (str): Host to wait for the scans to finish.
        operation_data (Dict): Dictionary with the operation data.
        current_datetime (str): Current datetime to use in the operation.
    """
    logging.info(f"Waiting for syscollector scan to finish on {host}")

    timeout_syscollector_scan = TIMEOUT_SYSCOLLECTOR_SHORT_SCAN if 'timeout_syscollector_scan' not in \
        operation_data else operation_data['timeout_syscollector_scan']

    # Wait until syscollector
    monitoring_data = generate_monitoring_logs(host_manager,
                                               [get_event_regex({'event': 'syscollector_scan_start'}),
                                                get_event_regex({'event': 'syscollector_scan_end'})],
                                               [timeout_syscollector_scan, timeout_syscollector_scan],
                                               host_manager.get_group_hosts('agent'))

    truncate_remote_host_group_files(host_manager, host_manager.get_group_hosts('agent'))

    monitoring_events_multihost(host_manager, monitoring_data)

    logging.info(f"Waiting for vulnerability scan to finish on {host}")

    wait_until_vuln_scan_agents_finished(host_manager)

    logging.info(f"Checking agent vulnerability on {host}")
