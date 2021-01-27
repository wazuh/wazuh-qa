# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import socket
import time

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector, Agent, create_agents
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

ANALYSISD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue')

SERVER_ADDRESS = 'localhost'
CRYPTO = "aes"

cases = [
    {
        'metadata': {
            'agents_number': 1,
            'agents_os': ['ubuntu20.04'],
            'protocol': 'tcp'
        }
    }
]

metadata = [case['metadata'] for case in cases]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, metadata=metadata)

# List where the agents objects will be stored
agents = []


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope="function")
def restart_service():
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


def wait_expected_line(line, expected):
    if (expected in line):
        return line
    return None


def test_os_exec(get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    injectors = []

    # Agents
    for agent in agents:
        injector = Injector(sender, agent)
        injectors.append(injector)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    agents_id = [int(x.id) for x in agents]

    # Give time for registration key to be available and send a few heartbeats
    time.sleep(10)

    for agent_id in agents_id:
        # Send upgrade request
        message = "8:[" + str(agent_id) + "] (vm-agent) 1.1.1.1->syscheck:{\"type\":\"event\",\"data\":{\"path\":\"/home/test/file\",\"mode\":\"realtime\",\"type\":\"added\",\"timestamp\":1575421292,\"attributes\":{\"type\":\"file\"}}}"
        send_message(message, ANALYSISD_SOCKET)
        # TODO

    for injector in injectors:
        injector.stop_receive()
