# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import socket
import time
import wazuh_testing.tools.agent_simulator as ag

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

ANALYSISD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue')

SERVER_ADDRESS = 'localhost'
SERVER_NAME = 'vm-test'
CRYPTO = 'aes'

AR_NAME = 'restart-wazuh'
RULE_ID = '5715'
LOG_LOCATION = 'any->logcollector'
SRC_IP = '172.16.5.15'
DST_USR = 'root'
ARG1 = '--argv1'
ARG2 = '--argv2'
AR_TIMEOUT = 10
LOG_MESSAGE = f'Jan 27 11:52:25 {SERVER_NAME} sshd[32046]: ' \
              f'Accepted password for {DST_USR} from {SRC_IP} port 62300 ssh2'

cases = [
    # Case 1: Local AR, new agent (version 4.2)
    {
        'params': {
            'AR_LOCATION': 'local',
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID,
            'EXTRA_ARGS': '',
            'TIMEOUT_ALLOWED': 'no',
            'TIMEOUT': 0
        },
        'metadata': {
            'agents_number': 1,
            'agents_os': ['ubuntu20.04'],
            'agents_version': ['v4.2.0'],
            'protocol': 'tcp',
            'extra_args': 'no',
            'timeout': 'no',
            'all_agents': 'no'
        }
    },
    # Case 2: Local AR, old agent (version < 4.2)
    {
        'params': {
            'AR_LOCATION': 'local',
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID,
            'EXTRA_ARGS': '',
            'TIMEOUT_ALLOWED': 'no',
            'TIMEOUT': 0
        },
        'metadata': {
            'agents_number': 1,
            'agents_os': ['debian8'],
            'agents_version': ['v4.1.0'],
            'protocol': 'tcp',
            'extra_args': 'no',
            'timeout': 'no',
            'all_agents': 'no'
        }
    },
    # Case 3: Local AR, old and new agent
    {
        'params': {
            'AR_LOCATION': 'local',
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID,
            'EXTRA_ARGS': '',
            'TIMEOUT_ALLOWED': 'no',
            'TIMEOUT': 0
        },
        'metadata': {
            'agents_number': 2,
            'agents_os': ['debian8', 'ubuntu20.04'],
            'agents_version': ['v4.1.0', 'v4.2.0'],
            'protocol': 'tcp',
            'extra_args': 'no',
            'timeout': 'no',
            'all_agents': 'no'
        }
    },
    # Case 4: Local AR, old and new agent with extra_args
    {
        'params': {
            'AR_LOCATION': 'local',
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID,
            'EXTRA_ARGS': f'{ARG1} {ARG2}',
            'TIMEOUT_ALLOWED': 'no',
            'TIMEOUT': 0
        },
        'metadata': {
            'agents_number': 2,
            'agents_os': ['debian8', 'ubuntu20.04'],
            'agents_version': ['v4.1.0', 'v4.2.0'],
            'protocol': 'tcp',
            'extra_args': 'yes',
            'timeout': 'no',
            'all_agents': 'no'
        }
    },
    # Case 5: Local AR, old and new agent with timeout
    {
        'params': {
            'AR_LOCATION': 'local',
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID,
            'EXTRA_ARGS': '',
            'TIMEOUT_ALLOWED': 'yes',
            'TIMEOUT': AR_TIMEOUT
        },
        'metadata': {
            'agents_number': 2,
            'agents_os': ['debian8', 'ubuntu20.04'],
            'agents_version': ['v4.1.0', 'v4.2.0'],
            'protocol': 'tcp',
            'extra_args': 'no',
            'timeout': 'yes',
            'all_agents': 'no'
        }
    },
    # Case 6: All AR, old and new agent
    {
        'params': {
            'AR_LOCATION': 'all',
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID,
            'EXTRA_ARGS': '',
            'TIMEOUT_ALLOWED': 'no',
            'TIMEOUT': 0
        },
        'metadata': {
            'agents_number': 2,
            'agents_os': ['debian8', 'ubuntu20.04'],
            'agents_version': ['v4.1.0', 'v4.2.0'],
            'protocol': 'tcp',
            'extra_args': 'no',
            'timeout': 'no',
            'all_agents': 'yes'
        }
    }
]

params = [case['params'] for case in cases]
metadata = [case['metadata'] for case in cases]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# List where the agents objects will be stored
agents = []


@pytest.fixture(scope="session")
def set_debug_mode():
    """
    Set remoted daemon in debug mode
    """
    local_int_conf_path = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    debug_line = 'remoted.debug=2\n'
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope="function")
def restart_service():
    """Restart Wazuh manager service and clean log file"""
    control_service('stop')
    clean_logs()
    control_service('start')
    yield


@pytest.fixture(scope="function")
def configure_agents(request, get_configuration):
    """Create simulated agents for test"""
    metadata = get_configuration.get('metadata')
    agents_number = metadata['agents_number']
    agents_os = metadata['agents_os']
    agents_version = metadata['agents_version']
    agents_created = ag.create_agents(agents_number, SERVER_ADDRESS, CRYPTO, agents_os=agents_os,
                                      agents_version=agents_version)
    setattr(request.module, 'agents', agents_created)


def send_message(data_object, socket_path):
    """Send a message to a given UNIX socket

    Args:
        data_object (str): Message to be sent
        socket_path (str): Location of the UNIX socket
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect(socket_path)
        sock.send(data_object.encode())


def clean_logs():
    """Clean log file"""
    truncate_file(LOG_FILE_PATH)


def wait_ar_line(line):
    """Callback function to wait for the Active Response message"""
    if 'Active response request received: ' in line:
        return line.split('Active response request received: ', 1)[1]

    return None


def validate_old_ar_message(agent_id, message, extra_args, timeout, all_agents):
    """Function to validate Active Response messages in old string format

    Args:
        agent_id (str): Agent ID or list of agent IDs.
        message (str): Message to be analyzed.
        extra_args (str): If 'yes', validate extra_args.
        timeout (str): If 'yes', validate timeout in Active Response name.
        all_agents (str): If 'yes', validate that message was sent to specific agent.
    """
    args = message.split()

    assert args[0] == '(local_source)', 'Event location did not match expected!'
    assert args[1] == '[]', 'Source IP did not match expected!'
    if all_agents == 'yes':
        assert args[2] == 'NNS', 'AR flags did not match expected!'
        assert args[3] in agent_id, 'Agent ID did not match expected!'
    else:
        assert args[2] == 'NRN', 'AR flags did not match expected!'
        assert args[3] == agent_id, 'Agent ID did not match expected!'

    if timeout == 'yes':
        assert args[4] == f'{AR_NAME}{AR_TIMEOUT}', 'AR name did not match expected!'
    else:
        assert args[4] == f'{AR_NAME}0', 'AR name did not match expected!'
    assert args[5] == DST_USR, 'Destination user did not match expected!'
    assert args[6] == SRC_IP, 'Source IP did not match expected!'
    assert args[8] == RULE_ID, 'Rule ID did not match expected!'
    if extra_args == 'yes':
        assert args[12] == ARG1, 'ARG1 did not match expected!'
        assert args[13] == ARG2, 'ARG2 did not match expected!'


def validate_new_ar_message(agent_id, message, extra_args, timeout, all_agents):
    """Function to validate Active Response messages in new JSON format

    Args:
        agent_id (str): Agent ID or list of agent IDs
        message (str): Message to be analyzed
        extra_args (str): If 'yes', validate extra_args
        timeout (str): If 'yes', validate timeout in Active Response name
        all_agents (str): If 'yes', validate that message was sent to specific agent
    """
    args = message.split(' ', 4)

    assert args[0] == f'(local_source)', 'Event location did not match expected!'
    assert args[1] == '[]', 'Source IP did not match expected!'

    if all_agents == 'yes':
        assert args[2] == 'NNS', 'AR flags did not match expected!'
        assert args[3] in agent_id, 'Agent ID did not match expected!'
    else:
        assert args[2] == 'NRN', 'AR flags did not match expected!'
        assert args[3] == agent_id, 'Agent ID did not match expected!'

    json_alert = json.loads(args[4])  # Alert in JSON
    assert json_alert['version'], 'Missing version in JSON message'
    assert json_alert['version'] == 1, 'Invalid version in JSON message'
    assert json_alert['origin'], 'Missing origin in JSON message'
    assert json_alert['origin']['module'], 'Missing module in JSON message'
    assert json_alert['origin']['module'] == 'wazuh-analysisd', 'Invalid module in JSON message'
    assert json_alert['command'], 'Missing command in JSON message'

    if timeout == 'yes':
        assert json_alert['command'] == f'{AR_NAME}{AR_TIMEOUT}', 'Invalid command in JSON message'
    else:
        assert json_alert['command'] == f'{AR_NAME}0', 'Invalid command in JSON message'

    assert json_alert['parameters'], 'Missing parameters in JSON message'
    assert json_alert['parameters']['alert'], 'Missing alert in JSON message'
    assert json_alert['parameters']['alert']['rule'], 'Missing rule in JSON message'
    assert json_alert['parameters']['alert']['rule']['id'], 'Missing rule ID in JSON message'
    assert json_alert['parameters']['alert']['rule']['id'] == RULE_ID, 'Invalid rule ID in JSON message'
    assert json_alert['parameters']['alert']['data'], 'Missing data in JSON message'
    assert json_alert['parameters']['alert']['data']['srcip'], 'Missing source IP in JSON message'
    assert json_alert['parameters']['alert']['data']['srcip'] == SRC_IP, 'Invalid source IP in JSON message'
    assert json_alert['parameters']['alert']['data']['dstuser'], 'Missing destination user in JSON message'
    assert json_alert['parameters']['alert']['data']['dstuser'] == DST_USR, 'Invalid destination user in JSON message'

    if extra_args == 'yes':
        assert json_alert['parameters']['extra_args'], 'Missing extra_args in JSON message'
        assert json_alert['parameters']['extra_args'][0] == ARG1, 'Missing arg1 in JSON message'
        assert json_alert['parameters']['extra_args'][1] == ARG2, 'Missing arg1 in JSON message'


# TESTS
def test_os_exec(set_debug_mode, get_configuration, configure_environment, restart_service, configure_agents):
    """Check if Active Response message is sent in correct format depending on agent version"""
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    extra_args = metadata['extra_args']
    timeout = metadata['timeout']
    all_agents = metadata['all_agents']
    sender = ag.Sender(SERVER_ADDRESS, protocol=protocol)
    log_monitor = FileMonitor(LOG_FILE_PATH)
    injectors = []

    # Agents
    for agent in agents:
        injector = ag.Injector(sender, agent)
        injectors.append(injector)
        injector.run()
        if protocol == "tcp":
            sender = ag.Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    agents_id = [agent.id for agent in agents]

    # Give time for registration key to be available and send a few heartbeats
    time.sleep(30)

    if all_agents == 'yes':
        message = f"1:({SERVER_NAME}) {LOG_LOCATION}:{LOG_MESSAGE}"
        send_message(message, ANALYSISD_SOCKET)

        for agent in agents:
            # Checking AR in logs
            try:
                log_monitor.start(timeout=60, callback=wait_ar_line)
            except TimeoutError:
                raise AssertionError("AR message took too much!")

            last_log = log_monitor.result()

            if agent.os == 'ubuntu20.04':
                # Version 4.2
                validate_new_ar_message(agents_id, last_log, extra_args, timeout, all_agents)
            else:
                # Version < 4.2
                validate_old_ar_message(agents_id, last_log, extra_args, timeout, all_agents)

    else:
        for agent in agents:
            message = f"1:[{agent.id}] ({agent.name}) {LOG_LOCATION}:{LOG_MESSAGE}"
            send_message(message, ANALYSISD_SOCKET)

            # Checking AR in logs
            try:
                log_monitor.start(timeout=60, callback=wait_ar_line)
            except TimeoutError as err:
                raise AssertionError("AR message tooks too much!")

            last_log = log_monitor.result()

            if agent.os == 'ubuntu20.04':
                # Version 4.2
                validate_new_ar_message(agent.id, last_log, extra_args, timeout, all_agents)
            else:
                # Version < 4.2
                validate_old_ar_message(agent.id, last_log, extra_args, timeout, all_agents)

    for injector in injectors:
        injector.stop_receive()
