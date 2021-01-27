# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import socket
import time

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector, Agent, create_agents
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

ANALYSISD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue')

SERVER_ADDRESS = 'localhost'
CRYPTO = 'aes'

AR_NAME = 'restart-wazuh'
RULE_ID = '5715'
LOG_LOCATION = 'any->logcollector'
SRC_IP = '172.16.5.15'
DST_USR = 'root'
LOG_MESSAGE = 'Jan 27 11:52:25 vm-test sshd[32046]: Accepted password for ' + DST_USR + ' from ' + SRC_IP + ' port 62300 ssh2'

cases = [
    {
        'params': {
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID
        },
        'metadata': {
            'agents_number': 1,
            'agents_os': ['ubuntu20.04'],
            'protocol': 'tcp'
        }
    },
    {
        'params': {
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID
        },
        'metadata': {
            'agents_number': 1,
            'agents_os': ['debian8'],
            'protocol': 'tcp'
        }
    },
    {
        'params': {
            'AR_NAME': AR_NAME,
            'RULE_ID': RULE_ID
        },
        'metadata': {
            'agents_number': 2,
            'agents_os': ['debian8', 'ubuntu20.04'],
            'protocol': 'tcp'
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
    clean_logs()
    control_service('restart')
    yield


@pytest.fixture(scope="function")
def configure_agents(request, get_configuration):
    metadata = get_configuration.get('metadata')
    agents_number = metadata['agents_number']
    agents_os = metadata['agents_os']
    agents_created = create_agents(agents_number, SERVER_ADDRESS, CRYPTO, os=agents_os)
    setattr(request.module, 'agents', agents_created)


def send_message(data_object, socket_path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(socket_path)
    sock.send(data_object.encode())
    sock.close()


def clean_logs():
    truncate_file(LOG_FILE_PATH)


def wait_ar_line(line):
    if ('Active response request received: ' in line):
        return line.split('Active response request received: ', 1)[1]
    return None


def validate_old_ar_message(agent, message):
    args = message.split()
    assert args[0] == f'({agent.name})', 'Agent name did not match expected!'
    assert args[1] == LOG_LOCATION, 'Event location did not match expected!'
    assert args[2] == 'NRN', 'AR flags did not match expected!'
    assert args[3] == agent.id, 'Agent ID did not match expected!'
    assert args[4] == f'{AR_NAME}0', 'AR name did not match expected!'
    assert args[5] == DST_USR, 'Destination user did not match expected!'
    assert args[6] == SRC_IP, 'Source IP did not match expected!'
    assert args[8] == RULE_ID, 'Rule ID did not match expected!'


def validate_new_ar_message(agent, message):
    args = message.split(' ', 4)
    assert args[0] == f'({agent.name})', 'Agent name did not match expected!'
    assert args[1] == LOG_LOCATION, 'Event location did not match expected!'
    assert args[2] == 'NRN', 'AR flags did not match expected!'
    assert args[3] == agent.id, 'Agent ID did not match expected!'

    json_alert = json.loads(args[4]) # Alert in JSON
    assert json_alert['version'], 'Missing version in JSON message'
    assert json_alert['version'] == 1, 'Invalid version in JSON message'
    assert json_alert['origin'], 'Missing origin in JSON message'
    assert json_alert['origin']['module'], 'Missing module in JSON message'
    assert json_alert['origin']['module'] == 'wazuh-analysisd', 'Invalid module in JSON message'
    assert json_alert['command'], 'Missing command in JSON message'
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


 # TESTS

def test_os_exec(set_debug_mode, get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    log_monitor = FileMonitor(LOG_FILE_PATH)
    injectors = []

    # Agents
    for agent in agents:
        injector = Injector(sender, agent)
        injectors.append(injector)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    # Give time for registration key to be available and send a few heartbeats
    time.sleep(15)

    for agent in agents:
        message = "1:[" + str(agent.id) + "] (" + agent.name + ") " + LOG_LOCATION + ":" + LOG_MESSAGE
        send_message(message, ANALYSISD_SOCKET)

        # Checking AR in logs
        try:
            log_monitor.start(timeout=10, callback=wait_ar_line)
        except TimeoutError as err:
            raise AssertionError("AR message tooks too much!")

        last_log = log_monitor.result()

        if agent.os == 'ubuntu20.04':
            # Version 4.2
            validate_new_ar_message(agent, last_log)
        else:
            # Version < 4.2
            validate_old_ar_message(agent, last_log)

    for injector in injectors:
        injector.stop_receive()
