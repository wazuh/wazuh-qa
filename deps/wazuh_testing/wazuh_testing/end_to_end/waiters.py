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


VD_FEED_UPDATE_COMPLETED_TIMEOUT = 3600
VD_FEED_UPDATE_INITIATED_TIMEOUT = 60
VD_INITIAL_SCAN_PER_AGENT_TIMEOUT = 15

def wait_until_vd_is_updated(host_manager: HostManager) -> None:
    """
    Wait until the vulnerability data is updated for all manager hosts.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """

    # Logs to monitor
    scanner_started_message = "INFO: Vulnerability scanner module started"
    feed_update_initiated_message = "INFO: Initiating update feed process"
    feed_update_complete_message = "INFO: Feed update process completed"

    # Generate and monitor initial scanner log
    initial_monitoring_data = generate_monitoring_logs(
        host_manager, [scanner_started_message],
        [VD_FEED_UPDATE_COMPLETED_TIMEOUT], host_manager.get_group_hosts('manager')
    )
    initial_results = monitoring_events_multihost(host_manager, initial_monitoring_data)

    # Check initial scanner log
    if any(scanner_started_message in result['found'] for result in initial_results.values()):
        logging.info("Vulnerability scanner has started. Waiting for feed update completion...")
        # Proceed to check feed initiated log
        initiated_monitoring_data = generate_monitoring_logs(
            host_manager, [feed_update_initiated_message],
            [VD_FEED_UPDATE_INITIATED_TIMEOUT], host_manager.get_group_hosts('manager')
        )
        initiated_results = monitoring_events_multihost(host_manager, initiated_monitoring_data)

        if any(feed_update_initiated_message in result['found'] for result in initiated_results.values()):
            logging.info("Feed update process initiated successfully. Waiting for feed update completion...")
            # Finally check completion log
            completion_monitoring_data = generate_monitoring_logs(
                host_manager, [feed_update_complete_message],
                [VD_FEED_UPDATE_COMPLETED_TIMEOUT], host_manager.get_group_hosts('manager')
            )
            completion_results = monitoring_events_multihost(host_manager, completion_monitoring_data)
            if any(feed_update_complete_message in result['found'] for result in completion_results.values()):
                logging.info("Feed update process completed successfully")
            else:
                raise TimeoutError("Timeout waiting for the feed update process to complete")
        else:
            logging.info("Feed update initiated log not found, the feed has already been updated previously")
    else:
        logging.info("Scanner start log not found")

def wait_until_vuln_scan_agents_finished(host_manager: HostManager, agent_list: list = None) -> None:
    """
    Wait until vulnerability scans for all agents are finished.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """
    hosts_to_wait = agent_list if agent_list else host_manager.get_group_hosts('agent')
    final_timeout = VD_INITIAL_SCAN_PER_AGENT_TIMEOUT * len(hosts_to_wait)

    time.sleep(final_timeout)


def wait_syscollector_and_vuln_scan(host_manager: HostManager, syscollector_scan: int,
                                    greater_than_timestamp: str = '',
                                    agent_list: list = None) -> None:
    """
    Wait until syscollector and vulnerability scans are finished for a specific host.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
        host (str): Host to wait for the scans to finish.
        operation_data (Dict): Dictionary with the operation data.
        current_datetime (str): Current datetime to use in the operation.
    """
    logging.info(f"Waiting for syscollector scan to finish in all hosts")
    hosts_to_wait = agent_list if agent_list else host_manager.get_group_hosts('agent')

    # Wait until syscollector
    monitoring_data = generate_monitoring_logs(host_manager,
                                               [get_event_regex({'event': 'syscollector_scan_start'}),
                                                get_event_regex({'event': 'syscollector_scan_end'})],
                                               [syscollector_scan, syscollector_scan],
                                               hosts_to_wait, greater_than_timestamp=greater_than_timestamp)

    monitoring_events_multihost(host_manager, monitoring_data, ignore_timeout_error=False)

    logging.info(f"Waiting for vulnerability scan to finish")

    wait_until_vuln_scan_agents_finished(host_manager, agent_list=agent_list)
