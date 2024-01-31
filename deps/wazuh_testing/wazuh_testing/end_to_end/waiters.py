"""
Module to handle waiters for the end-to-end tests.
-----------------------------------------------------

This module provides functions for waiting until vulnerability data is updated for all manager hosts and until
vulnerability scans for all agents are finished.

Functions:
    - wait_until_vd_is_updated: Wait until the vulnerability data is updated for all manager hosts.
    - wait_until_vuln_scan_agents_finished: Wait until vulnerability scans for all agents are finished.

Constants:
    - VD_FEED_UPDATE_TIMEOUT: Time in seconds to wait until the vulnerability data is updated for all manager hosts.
    - VD_INITIAL_SCAN_PER_AGENT_TIMEOUT: Time in seconds to wait until vulnerability scans for each agent is finished.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import time

from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs, monitoring_events_multihost
from wazuh_testing.end_to_end.wazuh_api import get_agents_id
from wazuh_testing.tools.system import HostManager


VD_FEED_UPDATE_TIMEOUT = 300
VD_INITIAL_SCAN_PER_AGENT_TIMEOUT = 15


def wait_until_vd_is_updated(host_manager: HostManager) -> None:
    """
    Wait until the vulnerability data is updated for all manager hosts.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """

    monitoring_data = generate_monitoring_logs(host_manager, ["INFO: Action for 'vulnerability_feed_manager' finished"],
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
