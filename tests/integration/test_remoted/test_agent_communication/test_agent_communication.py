# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import time
import os
import pytest
import socket

import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing.tools.configuration import load_wazuh_configurations
from deps.wazuh_testing.wazuh_testing.tools.services import wait_for_remote_connection
from wazuh_testing import wazuh_db as wdb

# Marks

pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_communication.yaml')

parameters = [
    {'PROTOCOL': 'tcp'},
    {'PROTOCOL': 'udp'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=parameters)
config_ids = [x['PROTOCOL'] for x in parameters]

# Utils
request_socket = '/var/ossec/queue/ossec/request'
manager_address = "localhost"


def create_agent(protocol="tcp"):
    wait_for_remote_connection(protocol=protocol)
    agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0", debug=True)
    sender = ag.Sender(manager_address, protocol=protocol)
    injector = ag.Injector(sender, agent)
    injector.run()
    agent.wait_status_active()
    return agent


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_disconnected_agent(get_configuration, configure_environment, restart_remoted):
    cfg = get_configuration['metadata']
    protocol = cfg['PROTOCOL']

    agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0", debug=True)

    msg_request = f'{agent.id} {command_request}'

    if protocol == "UDP":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        request_msg = msg_request.encode()
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        request_size = len(bytearray(msg_request, 'utf-8'))
        request_msg = request_size.to_bytes(4, 'little') + msg_request.encode()

    sock.connect(request_socket)
    sock.send(request_msg)
    response = sock.recv(100).decode()


@pytest.mark.parametrize("command_request", ['agent getconfig client'])
def test_message(get_configuration, configure_environment, restart_remoted):
    """
    Writes a statistics request in $DIR/queue/ossec/request and check if remoted forwards it to the agent,
    collects the response, and writes it in the socket.
    """

    cfg = get_configuration['metadata']
    protocol = cfg['PROTOCOL']

    agent = create_agent(protocol)

    msg_request = f'{agent.id} {command_request}'

    if protocol == "UDP":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        request_msg = msg_request.encode()
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        request_size = len(bytearray(msg_request, 'utf-8'))
        request_msg = request_size.to_bytes(4, 'little') + msg_request.encode()

    sock.connect(request_socket)
    sock.send(request_msg)
    response = sock.recv(100).decode()

    assert 'ok' in response, "Error in remoted response"
    assert '{"client":{"config-profile":"centos8","notify_time":10,"time-reconnect":60}}' in response


