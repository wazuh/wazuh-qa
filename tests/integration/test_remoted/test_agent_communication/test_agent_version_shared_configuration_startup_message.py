'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, these tests will check if the agent status appears as 'disconnected' after
       just sending the 'start-up' event, sent by several agents using different protocols.
       Agent's status should change from 'disconnected' to 'active' status after the manager
       receives the agents' keep-alive message.

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
    - https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html?highlight=status#agent-status

tags:
    - remoted
'''
import os
from time import sleep

import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import UDP, TCP, TCP_UDP, remote
from wazuh_testing.remote import check_push_shared_config, REMOTED_GLOBAL_TIMEOUT
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = pytest.mark.tier(level=2)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_version_shared_configuration_startup_message.yaml')
agent_conf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'agent.conf')

parameters = [
    {'PROTOCOL': TCP},
    {'PROTOCOL': UDP},
    {'PROTOCOL': TCP_UDP}
]

metadata = [
    {'protocol': TCP},
    {'protocol': UDP},
    {'protocol': TCP_UDP}
]

agent_info = {
    'debian7_420': {
        'manager_address': '127.0.0.1',
        'os': 'debian7',
        'version': 'v4.2.0',
        'disable_all_modules': True
    },
    'debian9_4.4.0': {
        'manager_address': '127.0.0.1',
        'os': 'debian9',
        'version': 'v4.4.0',
        'disable_all_modules': True
    }
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [x['PROTOCOL'] for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("agent_name", agent_info.keys())
def test_agent_remote_configuration(agent_name, get_configuration, configure_environment, remove_shared_files,
                                    restart_remoted, create_agent_group):
    '''
    description: Check if the manager sends the shared configuration to agents through remote,
                 ensuring the agent version is correct.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - agent_name:
            type: dict_keys
            brief: Number of agents to create and check their status.
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
            brief: Reset ossec.log and start a new monitor.
        - create_agent_group:
            type: fixture
            brief: Temporary creates a new agent group for testing purpose, must be run only on Managers.

    assertions:
        - Verify that the shared configuration was sent, checking the agent version retrieved by 'wazuh_bd'
        - Verify the startup message was received.

    input_description: A configuration template (test_agent_version_shared_configuration_startup_message) is contained
                       in an external YAML file (wazuh_agent_version_shared_configuration_startup_message.yaml).
                       That template is combined with different test cases defined in the module. Those include
                       configuration settings for the 'wazuh-remoted' daemon and agents info.

    expected_output:
        - fr"DEBUG: Agent <agent_name> sent HC_STARTUP from 127.0.0.1"
        - The start up message has not been found in the logs

    tags:
        - simulator
        - wazuh_db
        - remoted
    '''
    protocols = get_configuration['metadata']['protocol']

    for protocol in protocols.split(","):
        agent = ag.Agent(**agent_info[agent_name])

        # Sleep to avoid ConnectionRefusedError
        sleep(REMOTED_GLOBAL_TIMEOUT)

        sender = ag.Sender(agent_info[agent_name]['manager_address'], protocol=protocol)

        check_push_shared_config(agent, sender)

        wazuh_db_agent_version = agent.get_agent_version()
        assert wazuh_db_agent_version == fr"Wazuh {agent_info[agent_name]['version']}"
