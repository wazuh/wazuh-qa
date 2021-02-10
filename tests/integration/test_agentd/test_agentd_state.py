# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import sys
from time import sleep

import pytest
import yaml
from wazuh_testing.agent import (set_state_interval, callback_ack, callback_keepalive,
                                 callback_connected_to_server, callback_state_file_updated)
from wazuh_testing.fim import change_internal_options
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service

from conftest import CLIENT_KEYS_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_data_file = os.path.join(test_data_path, 'wazuh_state_tests.yaml')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Open test cases description file
with open(test_data_file) as f:
    test_cases = yaml.safe_load(f)

# Global RemotedSimulator variable
remoted_server = None
# Global FileMonitor variable to watch ossec.log
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Variables
if sys.platform == 'win32':
    state_file_path = os.path.join(WAZUH_PATH, 'wazuh-agent.state')
    internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')
else:
    state_file_path = os.path.join(WAZUH_PATH, 'var', 'run', 'wazuh-agentd.state')
    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')


# Fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


# Functions
def extra_configuration_before_yield():
    change_internal_options('agent.debug', '2')


def extra_configuration_after_yield():
    global remoted_server
    if remoted_server is not None:
        remoted_server.stop()

    # Set default values
    change_internal_options('agent.debug', '0')
    set_state_interval(5, internal_options)
    truncate_file(CLIENT_KEYS_PATH)


def add_custom_key():
    """Set test client.keys file"""
    with open(CLIENT_KEYS_PATH, 'w+') as client_keys:
        client_keys.write("100 ubuntu-agent any TopSecret")


# Tests
@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_agentd_state(configure_environment, test_case: list):
    global remoted_server
    if remoted_server is not None:
        remoted_server.stop()
    # Stop service
    control_service('stop')

    if 'interval' in test_case['input']:
        set_state_interval(test_case['input']['interval'], internal_options)
    else:
        set_state_interval(1, internal_options)

    # Truncate ossec.log in order to watch it correctly
    truncate_file(LOG_FILE_PATH)

    # Remove state file to check if agent behavior is as expected
    os.remove(state_file_path) if os.path.exists(state_file_path) else None

    # Add dummy key in order to communicate with RemotedSimulator
    add_custom_key()

    # Start service
    control_service('start')

    # Start RemotedSimulator if test case need it
    if 'remoted' in test_case['input'] and test_case['input']['remoted']:
        remoted_server = RemotedSimulator(protocol='tcp', mode='DUMMY_ACK', client_keys=CLIENT_KEYS_PATH)

    # Check fields for every expected output type
    for expected_output in test_case['output']:
        check_fields(expected_output)


def parse_state_file():
    """
    Parse state file and return the content as dict

    Returns:
        dict: state info
    """
    # Wait until state file is dumped
    wait_state_update()
    state = {}
    with open(state_file_path) as state_file:
        for line in state_file:
            line = line.rstrip('\n')
            # Remove empty lines or comments
            if not line or line.startswith('#'):
                continue
            (key, value) = line.split('=', 1)
            # Remove value's quotes
            state[key] = value.strip("'")

    return state


def remoted_get_state():
    """
    Send getstate request to agent (via RemotedSimulator) and return state info as dict.

    Returns:
        dict: state info
    """
    global remoted_server
    remoted_server.request('agent getstate')
    sleep(2)
    response = json.loads(remoted_server.request_answer)
    return response['data']


def check_fields(expected_output):
    """Check every field agains expected data

    Args:
        expected_output (dict): expected output block
    """
    checks = {
        'last_ack': {'handler': check_last_ack, 'precondition': [wait_ack]},
        'last_keepalive': {'handler': check_last_keepalive,
                           'precondition': [wait_keepalive]},
        'msg_count': {'handler': check_last_keepalive,
                      'precondition': [wait_keepalive]},
        'status': {'handler': check_status, 'precondition': []}
        }

    if expected_output['type'] == 'file':
        get_state = parse_state_file
    else:
        get_state = remoted_get_state

    for field, expected_value in expected_output['fields'].items():
        # Check if expected value is valiable and mandatory

        if expected_value != '':
            for precondition in checks[field].get('precondition'):
                precondition()
        assert checks[field].get('handler')(expected_value, get_state_callback=get_state)


def check_last_ack(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if get_state_callback:
        current_value = get_state_callback()['last_ack']
        if expected_value == '':
            return expected_value == current_value

    received_msg = "Received message: '#!-agent ack '"

    with open(LOG_FILE_PATH) as log:
        for line in log:
            if current_value.replace('-', '/') in line and received_msg in line:
                return True
    return False


def check_last_keepalive(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if get_state_callback:
        current_value = get_state_callback()['last_keepalive']
        if expected_value == '':
            return expected_value == current_value

    keep_alive_msg = 'Sending keep alive'
    agent_notification_msg = 'Sending agent notification'

    with open(LOG_FILE_PATH, 'r') as log:
        for line in log:
            if current_value.replace('-', '/') in line and (keep_alive_msg in line or agent_notification_msg in line):
                return True
    return False


def check_msg_count(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if get_state_callback:
        current_value = get_state_callback()['msg_count']
        if expected_value == '':
            return expected_value == current_value

    sent_messages = 0

    with open(LOG_FILE_PATH, 'r') as log:
        for line in log:
            if 'Sending keep alive' in line:
                sent_messages += 1

    return sent_messages >= current_value


def check_status(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if expected_value != 'pending':
        wait_keepalive(True)
        if get_state_callback == parse_state_file:
            wait_state_update(True)
    current_value = get_state_callback()['status']
    return expected_value == current_value


def wait_connect(update_position=False):
    """ Watch ossec.conf until `callback_connected_to_server` is triggered

    Args:
        update_position (bool, optional): update position after reading.
                                          Defaults to False.
    """
    global wazuh_log_monitor
    wazuh_log_monitor.start(timeout=120,
                            callback=callback_connected_to_server,
                            update_position=update_position,
                            error_message='Agent connected not found')


def wait_ack(update_position=False):
    """ Watch ossec.conf until `callback_ack` is triggered

    Args:
        update_position (bool, optional): update position after reading.
                                          Defaults to False.
    """
    global wazuh_log_monitor
    wazuh_log_monitor.start(timeout=120,
                            callback=callback_ack,
                            update_position=update_position,
                            error_message='Ack not found')


def wait_keepalive(update_position=False):
    """ Watch ossec.conf until `callback_keepalive` is triggered

    Args:
        update_position (bool, optional): update position after reading.
                                          Defaults to False.
    """
    global wazuh_log_monitor
    wazuh_log_monitor.start(timeout=120,
                            callback=callback_keepalive,
                            update_position=update_position,
                            error_message='Keepalive not found')


def wait_state_update(update_position=True):
    """ Watch ossec.conf until `callback_state_file_updated` is triggered

    Args:
        update_position (bool, optional): update position after reading.
                                          Defaults to True.
    """
    global wazuh_log_monitor
    wazuh_log_monitor.start(timeout=120,
                            callback=callback_state_file_updated,
                            update_position=update_position,
                            error_message='State file update not found')
