'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, these tests will send the shared configuration to the agent and check if
       the configuration is completely pushed.

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
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import UDP, TCP, TCP_UDP
from wazuh_testing.remote import check_push_shared_config, REMOTED_GLOBAL_TIMEOUT
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks

pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_shared_configuration.yaml')
agent_conf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'agent.conf')

parameters = [
    {'PROTOCOL': TCP},
    {'PROTOCOL': UDP},
    {'PROTOCOL': TCP_UDP},
]

metadata = [
    {'protocol': TCP},
    {'protocol': UDP},
    {'protocol': TCP_UDP},
]

agent_info = {
    'manager_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [x['PROTOCOL'] for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_push_shared_config(get_configuration, configure_environment, remove_shared_files,
                            restart_remoted, create_agent_group):
    '''
    description: Check if the manager pushes shared configuration to agents as expected.
                 For this purpose, the test will create an agent for each protocol within the module test cases. Then,
                 it will try to send the shared configuration to the agent and then, check if the configuration is
                 completely pushed.
                 For example, if Wazuh Manager sends new shared files from group shared folder when the merged.mg
                 checksum is received from an agent is different than the stored one.
                 As the test has nothing to do with shared configuration files, we removed those rootcheck txt files
                 from default agent group to reduce the time required by the test to make the checks.

    wazuh_min_version: 4.2.0

    tier: 1

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
        - create_agent_group:
            type: fixture
            brief: Temporary creates a new agent group for testing purpose, must be run only on Managers.

    assertions:
        - Verify that group file configuration is completely pushed (up message, configuration and close message).
        - Verify that new configuration is pushed.
        - Verify that the same config is not pushed two times.

    input_description: A configuration template (test_shared_configuration) is contained in an external YAML file,
                       (wazuh_shared_configuration.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-remoted' daemon and agents
                       info.

    expected_output:
        - initial up file message not received
        - agent.conf message not received
        - initial close message not received
        - Same shared configuration pushed twice!
        - New group shared config not received

    tags:
        - simulator
    '''

    protocols = get_configuration['metadata']['protocol']

    for protocol in protocols.split(","):
        agent = ag.Agent(**agent_info)
        # Sleep to avoid ConnectionRefusedError
        sleep(REMOTED_GLOBAL_TIMEOUT)
        sender = ag.Sender(agent_info['manager_address'], protocol=protocol)
        check_push_shared_config(agent, sender)
