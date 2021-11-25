'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

brief:
    These tests will check if the Syscollector events, which are processed by
    the `wazuh-analysisd` daemon, generates appropriate alerts based on the
    information contained in the delta.

tier:
    0

modules:
    - analysisd

components:
    - manager

path:
    tests/integration/test_analysisd/test_syscollector/test_syscollector_events.py

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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html#using-syscollector-information-to-trigger-alerts
'''
import json
import os
import shutil

import pytest
import yaml
from wazuh_testing.tools import (ALERT_FILE_PATH, LOG_FILE_PATH,
                                 WAZUH_UNIX_USER, WAZUH_UNIX_GROUP,
                                 CUSTOM_RULES_PATH, ANALYSISD_QUEUE_SOCKET_PATH)
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service
from wazuh_testing.vulnerability_detector import create_mocked_agent, delete_mocked_agent

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(TEST_DATA_PATH, 'syscollector.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)


# Fixtures
@pytest.fixture(scope='module')
def configure_custom_rules(get_configuration):
    """Configure a syscollector custom rules for testing.
    Restarting wazuh-analysisd is required to apply this changes.
    """
    source_rule = os.path.join(TEST_DATA_PATH, get_configuration['rule_file'])
    target_rule = os.path.join(CUSTOM_RULES_PATH, get_configuration['rule_file'])

    # copy custom rule with specific privileges
    shutil.copy(source_rule, target_rule)
    shutil.chown(target_rule, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)

    yield

    # remove custom rule
    os.remove(target_rule)


@pytest.fixture(scope='module')
def restart_analysisd():
    """wazuh-analysisd restart and log truncation"""
    required_logtest_daemons = ['wazuh-analysisd']

    truncate_file(ALERT_FILE_PATH)
    truncate_file(LOG_FILE_PATH)

    for daemon in required_logtest_daemons:
        control_service('restart', daemon=daemon)

    yield

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)


@pytest.fixture(scope='module')
def mock_agent():
    """Fixture to create a mocked agent in wazuh databases"""
    control_service('stop', daemon='wazuh-db')
    agent_id = create_mocked_agent(name="mocked_agent")
    control_service('start', daemon='wazuh-db')

    yield agent_id

    control_service('stop', daemon='wazuh-db')
    delete_mocked_agent(agent_id)
    control_service('start', daemon='wazuh-db')


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Variables
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]
receiver_sockets = None
wazuh_log_monitor = FileMonitor(ALERT_FILE_PATH)
alert_timeout = 5


# Tests
@pytest.mark.parametrize('test_case',
                         list(test_cases),
                         ids=[test_case['name'] for test_case in test_cases])
def test_syscollector_events(test_case, get_configuration, mock_agent, configure_custom_rules, restart_analysisd,
                             wait_for_analysisd_startup, connect_to_sockets_function):
    '''
    description:
        Check if Analysisd handle Syscollector deltas properly by generating alerts.

    wazuh_min_version:
        4.4.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - mock_agent:
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

    assertions:
        - Verify that specific syscollector deltas trigger specific custom alert with certain values.

    input_description:
        Input dataset (defined as event_header + event_payload in syscollector.yaml)
        cover, in most of the cases, INSERTED, MODIFIED and DELETED deltas
        for each of the available scan: osinfo, hwinfo, processes, packages, network_interface,
        network_address, network_protocol, ports and hotfixes.

    expected_output:
        Expected output (defined as alert_expected_values in syscollector.yaml)

    tags:
        - rules
    '''

    # Get mock agent_id to create syscollector header
    agent_id = mock_agent
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
        wazuh_log_monitor.start(timeout=alert_timeout,
                                callback=alert_callback,
                                error_message=f"Timeout expecting {stage['description']} message.")


class CallbackWithContext(object):
    def __init__(self, function, *ctxt):
        self.ctxt = ctxt
        self.function = function

    def __call__(self, param):
        return self.function(param, *self.ctxt)


def callback_check_syscollector_alert(alert, expected_alert):
    """Check if an alert meet certain criteria and values .
    Args:
        line (str): alert (json) to check.
        expected_alert (dict): values to check.
    Returns:
        True if line match the criteria. None otherwise
    """
    try:
        alert = json.loads(alert)
    except Exception:
        return None

    def dotget(dotdict, k):
        """Get value from dict using dot notation keys

        Args:
            dotdict (dict): dict to get value from
            k (str): dot-separated key.

        Returns:
            value of specified key. None otherwise
        """
        if '.' in k:
            key = k.split('.', 1)
            return dotget(dotdict[key[0]], key[1])
        else:
            return dotdict.get(k)

    for field in expected_alert.keys():
        current_value = dotget(alert, field)
        try:
            expected_value = json.loads(expected_alert[field])
            expected_value = expected_value if type(expected_value) is dict else str(expected_value)
        except ValueError as e:
            expected_value = str(expected_alert[field])

        if current_value != expected_value:
            return None

    return True
