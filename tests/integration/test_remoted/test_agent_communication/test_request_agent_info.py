'''
brief:
    Check that manager-agent communication through remoted socket works as expected.
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
modules:
    - remoted
daemons:
    - wazuh-remoted
os_platform:
    - linux
os_vendor:
    - redhat
    - debian
    - ubuntu
    - alas
    - arch-linux
os_version:
    - rhel5
    - rhel6
    - rhel7
    - rhel8
    - buster
    - stretch
    - wheezy
    - bionic
    - xenial
    - trusty
    - amazon-linux-1
    - amazon-linux-2
tiers:
    - 0
tags:
    - tcp
    - udp
    - authd
component:
    - manager
'''
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
    '''
    description:
        Writes (config/state) requests in $DIR/queue/ossec/request and check if remoted forwards it to the agent,
        collects the response, and writes it in the socket or returns an error message if the queried
        agent is disconnected.
    parameters:
        - remove_shared_files:
            type: fixture
            brief: Temporary removes txt files from default agent group shared files
        - restart_remoted:
            type: fixture
            brief: Reset ossec.log and start a new monitor
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
    wazuh_min_version:
        4.2
    behaviour:
        - Test getconfig request
        - Test getstate request
        - Test getconfig request for a disconnected agent
    expected_behaviour:
        - "Remoted unexpected answer"
    '''
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
