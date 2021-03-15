# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import time

import pytest

import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.sockets import send_request


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_request_agent_info.yaml')

parameters = [
    {'PROTOCOL': 'udp,tcp'},
    {'PROTOCOL': 'tcp'},
    {'PROTOCOL': 'udp'},
]

metadata = [
    {'PROTOCOL': 'udp,tcp'},
    {'PROTOCOL': 'tcp'},
    {'PROTOCOL': 'udp'},
]

# test cases

test_case = {
    'disconnected': ('agent getconfig disconnected',
                     'Cannot send request'),
    'get_config': ('agent getconfig client',
                   '{"client":{"config-profile":"centos8","notify_time":10,"time-reconnect":60}}'),
    'get_state': ('logcollector getstate',
                  '{"error":0,"data":{"global":{"start":"2021-02-26, 06:41:26","end":"2021-02-26 08:49:19"}}}')
}


configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [x['PROTOCOL'] for x in parameters]

# Utils
manager_address = "localhost"


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("command_request,expected_answer", test_case.values(), ids=list(test_case.keys()))
def test_request(get_configuration, configure_environment, remove_shared_files,
                 restart_remoted, command_request, expected_answer):
    """
    Writes (config/state) requests in $DIR/queue/ossec/request and check if remoted forwards it to the agent,
    collects the response, and writes it in the socket or returns an error message if the queried
    agent is disconnected.
    """
    cfg = get_configuration['metadata']
    protocols = cfg['PROTOCOL'].split(',')

    agents = [ag.Agent(manager_address, "aes", os="debian8", version="4.2.0") for _ in range(len(protocols))]
    for agent, protocol in zip(agents, protocols):
        if "disconnected" not in command_request:
            sender, injector = ag.connect(agent, manager_address, protocol)

        msg_request = f'{agent.id} {command_request}'

        response = send_request(msg_request)

        assert expected_answer in response, "Remoted unexpected answer"

        if "disconnected" not in command_request:
            injector.stop_receive()
