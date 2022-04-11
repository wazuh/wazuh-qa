'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: reliability

brief: Agents register their state in the file /var/ossec/var/run/wazuh-agentd.state. This state can vary between
       `disconnected`, `connected` and `pending` states. Similarly, the manager records the number of `tcp_sessions`
        in the file /var/ossec/var/run/wazuh-remoted.state. Under normal conditions, the agents should never disconnect
        and the tcp_sessions should be equal to the number of connected agents on the node.

tier: 0

modules:
    - agentd
    - remoted

components:
    - agent
    - manager

daemons:
    - wazuh-agentd
    - wazuh-remoted

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - macOS Server
    - macOS Catalina
    - macOS Sierra
    - Windows XP
    - Windows 7
    - Windows 8
    - Windows 10
    - Windows Server 2003
    - Windows Server 2012
    - Windows Server 2016
    - Windows Server 2019

tags:
    - remoted_agent_communication
    - remoted
    - agentd
'''
import pytest


def test_agent_connection(get_report):
    '''
    description: Check the agents do not disconnect during the environment time.

    wazuh_min_version: 4.4.0

    parameters:
        - get_report:
            type: fixture
            brief: Get the JSON environment report.

    assertions:
        - Verify all the agents remain in connected status during the environment time.

    input_description: JSON environment reports

    expected_output:
        - None
    '''
    wazuh_target_report_agentd = get_report['agents']['wazuh-agentd']
    wazuh_target_report_remoted = get_report['managers']['wazuh-remoted']

    error_messages = []
    # Ensure TCP sessions is equal to the number of agent
    if not wazuh_target_report_remoted['min_tcp_sessions'] == get_report['metadata']['n_agents']:
        error_messages += ['TCP sessions are not the same as the number of agents']

    # Ensure all agent status is connected during all the environment uptime
    if not wazuh_target_report_agentd['ever_disconnected'] == 0:
        error_messages += ['Some agents have disconnected']

    if not wazuh_target_report_agentd['ever_pending'] == 0:
        error_messages += ['Some agents have change to pending status']

    if not wazuh_target_report_agentd['begin_status']['connected'] == \
       wazuh_target_report_agentd['end_status']['connected'] == \
       get_report['metadata']['n_agents']:

        error_messages += ['Some agents statuses have not been gathered correctly']

    assert not error_messages, f"Some agent connection errors have been detected {error_messages}"
