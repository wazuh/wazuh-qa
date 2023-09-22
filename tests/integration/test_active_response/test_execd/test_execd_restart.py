'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Active responses execute a script in response to the triggering of specific alerts based
       on the alert level or rule group. These tests will check if the 'active responses',
       which are executed by the 'wazuh-execd' daemon via scripts, run correctly.

components:
    - active_response

suite: execd

targets:
    - agent

daemons:
    - wazuh-analysisd
    - wazuh-execd

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/#active-response
'''
import os
import platform
import pytest
import time
import subprocess

import wazuh_testing.execd as execd
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.remoted_sim import RemotedSimulator

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

CURRENT_PLATFORM = platform.system()
CONF_FOLDER = '' if CURRENT_PLATFORM == 'Windows' else 'etc'
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, CONF_FOLDER, 'client.keys')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, CONF_FOLDER, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, CONF_FOLDER, 'manager.cert')
CRYPTO = "aes"
SERVER_ADDRESS = '127.0.0.1'
PROTOCOL = "tcp"

test_metadata = [
    {
        'command': 'restart-wazuh0',
        'rule_id': '554',
        'results': {
            'success': True,
        }
    },
    {
        'command': 'restart-wazuh0',
        'rule_id': '554',
        'results': {
            'success': False,
        }
    },
]

params = [
    {
        'CRYPTO': CRYPTO,
        'SERVER_ADDRESS': SERVER_ADDRESS,
        'REMOTED_PORT': 1514,
        'PROTOCOL': PROTOCOL
    } for _ in range(len(test_metadata))
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=test_metadata)

remoted_simulator = None


@pytest.fixture(scope="function")
def start_agent(request, get_configuration):
    """Create Remoted and Authd simulators, register agent and start it.

    Args:
        get_configuration (fixture): Get configurations from the module.
    """
    agent_restart_failure = False
    metadata = get_configuration['metadata']
    authd_simulator = AuthdSimulator(server_address=SERVER_ADDRESS,
                                     enrollment_port=1515,
                                     key_path=SERVER_KEY_PATH,
                                     cert_path=SERVER_CERT_PATH)
    authd_simulator.start()
    global remoted_simulator
    remoted_simulator = RemotedSimulator(server_address=SERVER_ADDRESS,
                                         remoted_port=1514,
                                         protocol=PROTOCOL,
                                         mode='CONTROLLED_ACK',
                                         start_on_init=True,
                                         client_keys=CLIENT_KEYS_PATH)

    remoted_simulator.set_active_response_message(build_message(metadata, metadata['results']))

    # Clean client.keys file
    truncate_file(CLIENT_KEYS_PATH)
    time.sleep(1)

    try:
        control_service('stop')
        agent_auth_pat = 'bin' if platform.system() == 'Linux' else ''
        subprocess.call([f'{WAZUH_PATH}/{agent_auth_pat}/agent-auth', '-m',
                        SERVER_ADDRESS])
        control_service('start')

    except Exception:
        print("Failure to restart the agent")
        agent_restart_failure = True

    yield agent_restart_failure

    remoted_simulator.stop()
    authd_simulator.shutdown()


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    yield request.param


def wait_message_line(line):
    """Callback function to wait for Active Response JSON message."""
    if CURRENT_PLATFORM == 'Windows' and "active-response/bin/restart-wazuh.exe: {\"version\"" in line:
        return True
    elif "active-response/bin/restart-wazuh: {\"version\"" in line:
        return True
    return None


def wait_invalid_input_message_line(line):
    """Callback function to wait for error message."""
    return line if "Invalid input format" in line else None


def wait_shutdown_message_line(line):
    """Callback function to wait for Wazuh shutdown message."""
    return True if "Shutdown received. Deleting responses." in line else None


def build_message(metadata, expected):
    """Build Active Response message to be used in tests.

    Args:
        metadata (dict): Components must be: 'command' and 'rule_id'
        expected (dict): Only one component called 'success' with boolean value.
    """
    origin = '"name":"","module":"wazuh-analysisd"'
    rules = f'"level":5,"description":"Test.","id":{metadata["rule_id"]}'

    if not expected['success']:
        return '{"origin":{' + origin + '},"command":"' + metadata['command'] + \
               '","parameters":{"extra_args":[],"alert":{"rule":{' + rules + '}}}}'

    return '{"version":1,"origin":{' + origin + '},"command":"' + metadata['command'] + \
           '","parameters":{"extra_args":[],"alert":{"rule":{' + rules + '}}}}'


def test_execd_restart(set_debug_mode, get_configuration, test_version,
                       configure_environment, start_agent, set_ar_conf_mode):
    '''
    description: Check if 'restart-wazuh' command of 'active response' is executed correctly.
                 For this purpose, a simulated agent is used, to which the active response is sent.
                 This response includes the order to restart the Wazuh agent,
                 which must restart after receiving this response.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_debug_mode:
            type: fixture
            brief: Set execd daemon in debug mode.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - test_version:
            type: fixture
            brief: Validate Wazuh version.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - start_agent:
            type: fixture
            brief: Create Remoted and Authd simulators, register agent and start it.
        - set_ar_conf_mode:
            type: fixture
            brief: Configure Active Responses used in tests.

    assertions:
        - Verify that the 'active response' 'restart-wazuh' is received.
        - Verify that the agent is ready to restart.

    input_description: Different use cases are found in the test module and include
                       parameters for 'restart-wazuh' command and the expected result.

    expected_output:
        - r'DEBUG: Received message'
        - r'Shutdown received. Deleting responses.'
        - r'Starting'
        - r'active-response/bin/restart-wazuh'
        - r'Ended'
        - r'Invalid input format' (If the 'active response' fails)

    tags:
        - simulator
    '''

    # Check if the agent is restarted properly"
    assert not start_agent, 'The agent failed to restart successfully after enrolling the authentication simulator.'

    metadata = get_configuration['metadata']
    expected = metadata['results']
    ossec_log_monitor = FileMonitor(LOG_FILE_PATH)
    ar_log_monitor = FileMonitor(execd.AR_LOG_FILE_PATH)

    # Checking AR in ossec logs
    ossec_log_monitor.start(timeout=60, callback=execd.wait_received_message_line)

    # Checking AR in active-response logs (only in Linux systems)
    if CURRENT_PLATFORM == 'Linux':
        ar_log_monitor.start(timeout=60, callback=execd.wait_start_message_line)

    if expected['success']:
        ar_log_monitor.start(timeout=60, callback=wait_message_line)

        # Checking shutdown message in ossec logs
        ossec_log_monitor.start(timeout=60, callback=wait_shutdown_message_line)

        if CURRENT_PLATFORM == 'Linux':
            ar_log_monitor.start(timeout=60, callback=execd.wait_ended_message_line)
    else:
        ar_log_monitor.start(timeout=60, callback=wait_invalid_input_message_line)
