# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import yaml
import sys
import json

from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.fim import (change_internal_options)
from conftest import CLIENT_KEYS_PATH
from time import sleep
from wazuh_testing.agent import (callback_ack,
                                 callback_keepalive,
                                 callback_connected_to_server,
                                 callback_state_file_updated
                                 )
from wazuh_testing.tools.services import (control_service,
                                          check_if_process_is_running)


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32,
              pytest.mark.tier(level=0), pytest.mark.agent]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
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
    state_file_path = os.path.join(WAZUH_PATH, 'var', 'run',
                                   'wazuh-agentd.state')
    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')


# Fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


# Functions
def control_service_unconditionally(action, daemon=None):
    """Control services avoiding handling exception

    Args:
        action : {'stop', 'start', 'restart'}
            Action to be done with the service/daemon.
        daemon : str, optional
            Name of the daemon to be controlled.
                None to control the whole Wazuh service. Default `None`.
    """
    try:
        control_service(action, daemon=daemon)
    except Exception:
        pass


def extra_configuration_before_yield():
    change_internal_options('agent.debug', '2')


def extra_configuration_after_yield():
    global remoted_server
    if remoted_server is not None:
        remoted_server.stop()

    # Set default values
    change_internal_options('agent.debug', '0')
    set_state_interval(5)
    truncate_file(CLIENT_KEYS_PATH)


def set_state_interval(interval):
    """Set agent.state_interval value on internal_options.conf
    Args:
        interval:
            - Different than `None`: set agent.state_interval
                                     value on internal_options.conf
            - `None`: agent.state_interval will be removed
                      from internal_options.conf
    """
    if interval is not None:
        change_internal_options('agent.state_interval', interval,
                                opt_path=internal_options)
    else:
        new_content = ''
        with open(internal_options) as f:
            lines = f.readlines()

        for line in lines:
            new_line = line if 'agent.state_interval' not in line else ''
            new_content += new_line

        with open(internal_options, 'w') as f:
            f.write(new_content)


def files_setup():
    """Truncate ossec.log and remote state file"""
    truncate_file(LOG_FILE_PATH)
    os.remove(state_file_path) if os.path.exists(state_file_path) else None


def set_test_key():
    """Set test client.keys file"""
    with open(CLIENT_KEYS_PATH, 'w+') as f:
        f.write("100 ubuntu-agent any TopSecret")


# Tests
@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_agentd_state(configure_environment, test_case: list):
    global remoted_server
    if remoted_server is not None:
        remoted_server.stop()
    # Stop service
    control_service_unconditionally('stop')

    if 'interval' in test_case['input']:
        set_state_interval(test_case['input']['interval'])
    else:
        set_state_interval(1)

    files_setup()
    set_test_key()

    # Start service
    control_service_unconditionally('start')

    # Start RemotedSimulator if test case need it
    if('remoted' in test_case['input'] and
       test_case['input']['remoted']):
        remoted_server = RemotedSimulator(protocol='tcp', mode='DUMMY_ACK',
                                          client_keys=CLIENT_KEYS_PATH)

    # Check fields for every expected output type
    for expected_output in test_case['output']:
        check_fields(expected_output)


def parse_state_file():
    """Parse state file and return the content as dict"""

    # Wait until state file is dumped
    wait_state_update()
    state = {}
    with open(state_file_path) as f:
        lines = f.readlines()

    for line in lines:
        line = line.rstrip('\n')
        # Remove empty lines or comments
        if not line or line.startswith('#'):
            continue
        (key, value) = line.split('=', 1)
        # Remove value's quotes
        state[key] = value.strip("'")

    return state


def remoted_get_state():
    """Send getstate request to agent (via RemotedSimulator)
        and return state info as dict.

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
        assert checks[field].get('handler')(expected_value,
                                            get_state_callback=get_state)


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

    with open(LOG_FILE_PATH) as f:
        lines = f.readlines()

    for line in lines:
        if(current_value.replace("-", "/") in line
           and "Received message: '#!-agent ack '" in line):
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

    with open(LOG_FILE_PATH) as f:
        lines = f.readlines()

    for line in lines:
        if(current_value.replace('-', '/') in line and
           ('Sending keep alive' in line or
           'Sending agent notification' in line)):
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
    with open(LOG_FILE_PATH) as f:
        lines = f.readlines()

    for line in lines:
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
