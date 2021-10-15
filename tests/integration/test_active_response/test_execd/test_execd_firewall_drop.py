'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the active responses, which are executed by
       the `wazuh-execd` daemon via scripts, run correctly. Active responses
       execute a script in response to the triggering of specific alerts
       based on the alert level or rule group.

tier: 0

modules:
    - active_response

components:
    - agent

path: tests/integration/test_active_response/test_execd/test_execd_restart.py

daemons:
    - wazuh-analysisd
    - wazuh-authd
    - wazuh-execd
    - wazuh-remoted

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/#active-response
'''
import json
import os
import platform
import pytest
from subprocess import call, Popen, PIPE
import time

import wazuh_testing.execd as execd
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, 'etc', 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, 'etc', 'manager.cert')
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "tcp"

test_metadata = [
    {
        'command': 'firewall-drop5',
        'rule_id': '5715',
        'ip': '3.3.3.3',
        'results': {
            'success': True,
        }
    },
    {
        'command': 'firewall-drop0',
        'ip': '3.3.3.3',
        'rule_id': '5715',
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

    control_service('stop')
    agent_auth_pat = 'bin' if platform.system() == 'Linux' else ''
    call([f'{WAZUH_PATH}/{agent_auth_pat}/agent-auth', '-m', SERVER_ADDRESS])
    control_service('start')

    yield

    remoted_simulator.stop()
    authd_simulator.shutdown()


@pytest.fixture(scope="function")
def remove_ip_from_iptables(request, get_configuration):
    """Remove the test IP from iptables if it exist.

    Args:
        get_configuration (fixture): Get configurations from the module.
    """
    metadata = get_configuration['metadata']
    param = '{"version":1,"origin":{"name":"","module":"wazuh-execd"},"command":"delete",' \
            '"parameters":{"extra_args":[],"alert":{"data":{"srcip":"' + metadata['ip'] + \
            '","dstuser":"Test"}},"program":"/var/ossec/active-response/bin/firewall-drop"}}'
    firewall_drop_script_path = os.path.join(WAZUH_PATH, 'active-response/bin', 'firewall-drop')

    iptables_file = os.popen('iptables -L')
    for iptables_line in iptables_file:
        if metadata['ip'] in iptables_line:
            p = Popen([firewall_drop_script_path], stdout=PIPE, stdin=PIPE, stderr=PIPE)
            p.stdin.write('{}\n\0'.format(param).encode('utf-8'))
            p.stdin.close()

    time.sleep(1)

    iptables_file = os.popen('iptables -L')
    for iptables_line in iptables_file:
        if metadata['ip'] in iptables_line:
            raise AssertionError("Unable to remove IP from iptables")


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    yield request.param


def validate_ar_message(message, command_id):
    """Verify that Active Response JSON messages have a "command" field and that it is valid.

    Args:
        message (str): Serialized JSON message.
        command_id (int): Integer with command ID.
    """
    command = 'add' if command_id == 0 else 'delete'

    json_alert = json.loads(message)  # Alert in JSON
    assert json_alert['command'], 'Missing command in JSON message'
    assert json_alert['command'] == command, 'Invalid command in JSON message'


def wait_message_line(line):
    """Callback function to wait for Active Response JSON message.

    Args:
        line (str): String containing message.
    """
    if "{\"version\"" in line:
        return line.split("active-response/bin/firewall-drop: ", 1)[1]
    return None


def wait_invalid_input_message_line(line):
    """Callback function to wait for error message.

    Args:
        line (str): String containing message.
    """
    return True if "Cannot read 'srcip' from data" in line else None


def build_message(metadata, expected):
    """Build Active Response message to be used in tests.

    Args:
        metadata (dict): Components must be: 'command', 'rule_id' and 'ip'
        expected (dict): Only one component called 'success' with boolean value.
    """
    origin = '"name":"","module":"wazuh-analysisd"'
    rules = f'"level":5,"description":"Test.","id":{metadata["rule_id"]}'

    if not expected['success']:
        return '{"version":1,"origin":{' + origin + '},"command":"' + metadata['command'] + \
               '","parameters":{"extra_args":[],"alert":{"rule":{' + rules + '},"data":{"dstuser":"Test."}}}}'

    return '{"version":1,"origin":{' + origin + '},"command":"' + metadata['command'] + \
           '","parameters":{"extra_args":[],"alert":{"rule":{' + rules + \
           '},"data":{"dstuser":"Test.","srcip":"' + metadata['ip'] + '"}}}}'


def test_execd_firewall_drop(set_debug_mode, get_configuration, test_version, configure_environment,
                             remove_ip_from_iptables, start_agent, set_ar_conf_mode):
    '''
    description: Check if `firewall-drop` command of `active response` is executed correctly.
                 For this purpose, a simulated agent is used and the active response
                 is sent to it. This response includes an IP address that must be added
                 and removed from iptables, the Linux firewall.

    wazuh_min_version: 4.2

    parameters:
        - set_debug_mode:
            type: fixture
            brief: Set the `wazuh-execd` daemon in debug mode.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - test_version:
            type: fixture
            brief: Validate the Wazuh version.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - remove_ip_from_iptables:
            type: fixture
            brief: Remove the testing IP address from `iptables` if it exists.
        - start_agent:
            type: fixture
            brief: Create `wazuh-remoted` and `wazuh-authd` simulators, register agent and start it.
        - set_ar_conf_mode:
            type: fixture
            brief: Configure the active responses used in the test.

    assertions:
        - Verify that the testing IP address is added to `iptables`.
        - Verify that the testing IP address is removed from `iptables`.

    input_description: Different use cases are found in the test module and include
                       parameters for `firewall-drop` command and the expected result.

    expected_output:
        - r'DEBUG: Received message'
        - r'Starting'
        - r'active-response/bin/firewall-drop'
        - r'Ended'
        - r'Cannot read 'srcip' from data' (If the `active response` fails)

    tags:
        - simulator
    '''
    metadata = get_configuration['metadata']
    expected = metadata['results']
    ossec_log_monitor = FileMonitor(LOG_FILE_PATH)
    ar_log_monitor = FileMonitor(execd.AR_LOG_FILE_PATH)

    # Checking AR in ossec logs
    ossec_log_monitor.start(timeout=60, callback=execd.wait_received_message_line)

    # Checking AR in active-response logs
    ar_log_monitor.start(timeout=60, callback=execd.wait_start_message_line)

    if expected['success']:
        for command_id in range(2):
            ar_log_monitor.start(timeout=60, callback=wait_message_line)
            last_log = ar_log_monitor.result()
            validate_ar_message(last_log, command_id)

            ar_log_monitor.start(timeout=60, callback=execd.wait_ended_message_line)

            # Checking if the IP was added/removed in iptables
            iptables_file = os.popen('iptables -L')
            flag = False
            for iptables_line in iptables_file:
                if metadata['ip'] in iptables_line:
                    flag = True

            if not flag and command_id == 0:
                raise AssertionError("IP was not added to iptable")
            elif flag and command_id == 1:
                raise AssertionError("IP was not deleted from iptable")

            time.sleep(5)
    else:
        ar_log_monitor.start(timeout=60, callback=wait_invalid_input_message_line)
