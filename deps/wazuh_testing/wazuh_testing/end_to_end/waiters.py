"""
Vulnerability Data Update and Scan Monitoring Module.
-----------------------------------------------------

This module provides functions for waiting until vulnerability data is updated for all manager hosts and until vulnerability scans for all agents are finished.

Functions:
    - wait_until_vd_is_updated: Wait until the vulnerability data is updated for all manager hosts.
    - wait_until_vuln_scan_agents_finished: Wait until vulnerability scans for all agents are finished.

Dependencies:
    - wazuh_testing.end_to_end.monitoring: Module containing functions for generating monitoring logs and handling events.
    - wazuh_testing.end_to_end.wazuh_api: Module containing functions for retrieving agent IDs.
    - wazuh_testing.tools.system: Module providing the HostManager class for handling the environment.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs_manager, monitoring_events_multihost
from wazuh_testing.end_to_end.wazuh_api import get_agents_id
from wazuh_testing.tools.system import HostManager

import time


def wait_until_vd_is_updated(host_manager: HostManager) -> None:
    """
    Wait until the vulnerability data is updated for all manager hosts.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """
    monitoring_data = {}

    for manager in host_manager.get_group_hosts('manager'):
        monitoring_data = generate_monitoring_logs_manager(
            host_manager, manager, "INFO: Action for 'vulnerability_feed_manager' finished", 1000
        )

        monitoring_events_multihost(host_manager, monitoring_data)


def wait_until_vuln_scan_agents_finished(host_manager: HostManager) -> None:
    """
    Wait until vulnerability scans for all agents are finished.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """
    # The order of agents may not be guaranteed.
    # The Vulnerability Detector scans are ordered based on the agent ID.
    # We are currently awaiting completion of all scans globally,
    # with a timeout set to 5 minutes for each agent.
    final_timeout = 15 * len(host_manager.get_group_hosts('agent'))
    time.sleep(final_timeout)

    # for agent in host_manager.get_group_hosts('agent'):
    #    manager_host = host_manager.get_host_variables(agent)['manager']
    #    agents_id = get_agents_id(host_manager)
    #    agent_id = agents_id.get(agent, '')
    #    finished_scan_pattern = rf"Finished vulnerability assessment for agent '{agent_id}'"
    #
    #        monitoring_data = generate_monitoring_logs_manager(
    #            host_manager, manager_host, finished_scan_pattern, final_timeout
    #        )
    #
    #        monitoring_events_multihost(host_manager, monitoring_data)
