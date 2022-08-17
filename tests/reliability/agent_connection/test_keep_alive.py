'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: reliability

brief: Agents once they register to the manager, they will start communicating with the manager.
       In this process, they send a keep-alive message to the manager, which will respond in normal
       conditions with an ACK. The difference between keep-alive and ACK should not exceed 20 seconds.

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


MAX_DIFFERENCE_ACK_KEEP_ALIVE = 20


def test_keep_alives(get_report):
    '''
    description: Check if the communication between managers and agents works as expected.
    This test ensures that ACK and keep alive does not overcome the specified maximum. The condition is checked using
    the agentd statistics data and the keep-alives received by the manager in the logs file.

    wazuh_min_version: 4.4.0

    parameters:
        - get_report:
            type: fixture
            brief: Get the JSON environment report.

    assertions:
        - Verify agents maximum difference between ack and keepalive is less than specified maximum.
        - Verify that the max_difference between keeps alives of all the agents in the managers side is less that
        the specified maximum.
        - Verify the number of keepalives of each agent is the expected.

    input_description: JSON environment reports

    expected_output:
        - None
    '''
    # Agent
    assert get_report['agents']['wazuh-agentd']['max_diff_ack_keep_alive'] < MAX_DIFFERENCE_ACK_KEEP_ALIVE, \
        f"Some agents keep alive interval surpassed {MAX_DIFFERENCE_ACK_KEEP_ALIVE} seconds maximun"

    # Manager
    keep_alives = get_report['managers']['wazuh-remoted']['keep_alives']

    max_differences = [keep_alives[agent]['max_difference'] for agent in keep_alives.keys()]
    assert max(max_differences) < MAX_DIFFERENCE_ACK_KEEP_ALIVE, \
        f"Some managers received keep-alives from agents at an interval that exceeded {MAX_DIFFERENCE_ACK_KEEP_ALIVE}" \
        + 'seconds maximun'

    remainder = [keep_alives[agent]['remainder'] for agent in keep_alives.keys()]
    assert max(remainder) < MAX_DIFFERENCE_ACK_KEEP_ALIVE, \
        'Some managers does not received keep-alives from agents at the required interval' + \
        f"{MAX_DIFFERENCE_ACK_KEEP_ALIVE} seconds maximun"
