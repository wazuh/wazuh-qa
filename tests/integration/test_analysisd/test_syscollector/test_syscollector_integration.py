'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if Analysisd handle Syscollector deltas
       properly by generating alerts.

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
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html\
        #using-syscollector-information-to-trigger-alerts
'''
import os
import pytest

from wazuh_testing.tools.configuration import get_test_cases_data
from wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH, ALERT_FILE_PATH
from wazuh_testing.analysis import CallbackWithContext, callback_check_syscollector_alert

pytestmark = [pytest.mark.server]

# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
TEST_RULES_PATH = os.path.join(TEST_DATA_PATH, 'rules')

local_internal_options = {'analysisd.debug': '2'}
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]
receiver_sockets = None
alert_timeout = 5
file_to_monitor = ALERT_FILE_PATH

# ---------------------------------------- TEST_SYSCOLLECTOR_EVENTS -------------------------------------
# Configuration and cases data
cases_path = os.path.join(TEST_CASES_PATH, 'cases_syscollector_integration.yaml')
rule_file = "syscollector_rules.xml"

# Enabled test configurations
_, configuration_metadata, case_ids = get_test_cases_data(cases_path)


@pytest.mark.tier(level=2)
@pytest.mark.parametrize('metadata', configuration_metadata, ids=case_ids)
def test_syscollector_integration(metadata, configure_local_internal_options_module, mock_agent_module,
                                  configure_custom_rules, restart_analysisd, wait_for_analysisd_startup,
                                  connect_to_sockets_function, file_monitoring):
    """
    description: Check if Analysisd handle Syscollector deltas properly by generating alerts.

    wazuh_min_version: 4.4.0

    tier: 2

    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
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
        Input dataset (defined as event_header + event_payload in cases_syscollector_integration.yaml)
        cover, in most of the cases, INSERTED, MODIFIED and DELETED deltas
        for each of the available scan; osinfo, hwinfo, processes, packages, network_interface,
        network_address, network_protocol, ports and hotfixes.

    expected_output:
        Expected output (defined as alert_expected_values in cases_syscollector_integration.yaml)

    tags:
        - rules
    """

    # Get mock agent_id to create syscollector header
    agent_id = mock_agent_module
    event_header = f"d:[{agent_id}] {metadata['event_header']}"

    # Add agent_id alert check
    alert_expected_values = metadata['alert_expected_values']
    alert_expected_values['agent.id'] = agent_id

    # Create full message by header and payload concatenation
    test_msg = event_header + metadata['event_payload']

    # Send delta to analysisd queue
    receiver_sockets[0].send(test_msg)

    # Set callback according to stage parameters
    alert_callback = CallbackWithContext(callback_check_syscollector_alert, alert_expected_values)

    # Find expected outputs
    log_monitor.start(timeout=alert_timeout,
                      callback=alert_callback,
                      error_message=f"Timeout expecting {metadata['description']} message.")
