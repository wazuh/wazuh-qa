'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, these tests will check that the manager can communicate correctly with the
       agent to ask for its information.

components:
    - remoted

suite: agent_communication

targets:
    - manager

daemons:
    - wazuh-remoted

os_platform:
    - linux

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

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html
    - https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html

tags:
    - remoted
'''
import os
from time import sleep

import pytest

import wazuh_testing.remote as rd
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.sockets import send_request
from wazuh_testing.tools import REMOTED_SOCKET_PATH


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_request_agent_info.yaml')

parameters = [
    {'PROTOCOL': 'udp,tcp'}
]

metadata = [
    {'PROTOCOL': 'udp,tcp'}
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

timeout_remoted_socket = 15

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
    description: Check that there are no problems when the manager tries to communicate with an agent to ask for
                 configuration or state files using the remoted socket. For this purpose, the test will create agents
                 and then, for each agent, it will wait until the agent key is loaded by remoted. After that, a request
                 is sent depending on the test case, and it checks if the response is the expected one for that case.
                 If the agent is disconnected, it raises an error.
                 As the test has nothing to do with shared configuration files, we removed those rootcheck txt files
                 from default agent group to reduce the time required by the test to make the checks.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - remove_shared_files:
            type: fixture
            brief: Temporary removes txt files from default agent group shared files.
        - restart_remoted:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - command_request:
            type: dict_values
            brief: Test cases values. Used to check the remoted socket status.
        - expected_answer:
            type: dict_keys
            brief: Test cases keys. Used to verify the remoted response.

    assertions:
        - Verify that the expected answer is in the response.

    input_description: A configuration template (test_request_agent_info) is contained in an external YAML file,
                       (wazuh_request_agent_info.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-remoted' daemon and agents
                       info.

    expected_output:
        - Could not find the remoted key loading log
        - "expected_answer: {agent.id} {command_request}"
        - Remoted unexpected answer

    tags:
        - simulator
        - remoted
    '''
    cfg = get_configuration['metadata']
    protocols = cfg['PROTOCOL'].split(',')

    agents = [ag.Agent(manager_address, "aes", os="debian8", version="4.2.0") for _ in range(len(protocols))]
    for agent, protocol in zip(agents, protocols):
        # Wait until remoted has loaded the new agent key
        rd.wait_to_remoted_key_update(wazuh_log_monitor)

        if "disconnected" not in command_request:
            sender, injector = ag.connect(agent, manager_address, protocol)
        else:
            # Give time for the remoted socket to be ready.
            sleep(timeout_remoted_socket)

        msg_request = f'{agent.id} {command_request}'

        response = send_request(msg_request, wazuh_socket=REMOTED_SOCKET_PATH)

        assert expected_answer in response, "Remoted unexpected answer"

        if "disconnected" not in command_request:
            injector.stop_receive()
