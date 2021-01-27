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
CRYPTO = "aes"

cases = [
    {
        'metadata': {
            'agents_number': 1,
            'agents_os': ['ubuntu20.04'],
            'protocol': 'tcp',
            'log_message': 'Jan 27 11:52:25 vm-test sshd[32046]: Accepted password for root from 172.16.5.15 port 62300 ssh2'
        }
    }
]

metadata = [case['metadata'] for case in cases]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, metadata=metadata)

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
        return line
    return None


def test_os_exec(set_debug_mode, get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    log_message = metadata['log_message']
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
        message = "1:[" + str(agent.id) + "] (" + agent.name + ") any->logcollector:" + log_message
        send_message(message, ANALYSISD_SOCKET)

        # Checking AR in logs
        try:
            log_monitor.start(timeout=10, callback=wait_ar_line)
        except TimeoutError as err:
            raise AssertionError("AR message tooks too much!")

        last_log = log_monitor.result()
        assert '' in last_log, \
            'AR did not match expected!'

    for injector in injectors:
        injector.stop_receive()
