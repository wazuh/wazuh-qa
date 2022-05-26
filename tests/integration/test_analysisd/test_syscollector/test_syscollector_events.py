'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the Syscollector events, which are processed by
       the `wazuh-analysisd` daemon, generates appropriate alerts based on the
       information contained in the delta.


components:
    - analysisd

suite: syscollector

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html#using-syscollector-information-to-trigger-alerts
'''
import os
import yaml
import pytest

from wazuh_testing.tools import (ANALYSISD_QUEUE_SOCKET_PATH, ALERT_FILE_PATH)
from wazuh_testing.analysis import CallbackWithContext, callback_check_syscollector_alert


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Variables
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]
receiver_sockets = None
alert_timeout = 5
file_to_monitor = ALERT_FILE_PATH

# Configurations
data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(data_dir, 'syscollector.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)


# Fixtures
@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
# @pytest.mark.skip(reason='Temporarily disabled until merge this PR https://github.com/wazuh/wazuh/pull/10843')
@pytest.mark.parametrize('test_case',
                         list(test_cases),
                         ids=[test_case['name'] for test_case in test_cases])
def test_syscollector_events(test_case, get_configuration, mock_agent_module, configure_custom_rules, restart_analysisd,
                             wait_for_analysisd_startup, connect_to_sockets_function, file_monitoring):
    '''
    description: Check if Analysisd handle Syscollector deltas properly by generating alerts.

    wazuh_min_version: 4.4.0

    tier: 2

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - mock_agent_module:
            type: fixture
            brief: Create mock agent and get agent_id
        - configure_custom_rules:
            type: fixture
            brief: Copy custom rules to test.
        - restart_analysisd:
            type: fixture
            brief: Restart analysisd daemon and truncate related log files.
        - wait_for_analysisd_startup:
            type: fixture
            brief: Wait until analysisd is ready.
        - connect_to_sockets_function:
            type: fixture
            brief: Connect to analysisd event queue.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.

    assertions:
        - Verify that specific syscollector deltas trigger specific custom alert with certain values.

    input_description:
        Input dataset (defined as event_header + event_payload in syscollector.yaml)
        cover, in most of the cases, INSERTED, MODIFIED and DELETED deltas
        for each of the available scan; osinfo, hwinfo, processes, packages, network_interface,
        network_address, network_protocol, ports and hotfixes.

    expected_output:
        Expected output (defined as alert_expected_values in syscollector.yaml)

    tags:
        - rules
    '''

    # Get mock agent_id to create syscollector header
    agent_id = mock_agent_module
    event_header = f"d:[{agent_id}] {test_case['event_header']}"

    for stage in test_case['test_case']:

        # Add agent_id alert check
        alert_expected_values = stage['alert_expected_values']
        alert_expected_values['agent.id'] = agent_id

        # Create full message by header and payload concatenation
        test_msg = event_header + stage['event_payload']

        # Send delta to analysisd queue
        receiver_sockets[0].send(test_msg)

        # Set callback according to stage parameters
        alert_callback = CallbackWithContext(callback_check_syscollector_alert, alert_expected_values)

        # Find expected outputs
        log_monitor.start(timeout=alert_timeout,
                          callback=alert_callback,
                          error_message=f"Timeout expecting {stage['description']} message.")
