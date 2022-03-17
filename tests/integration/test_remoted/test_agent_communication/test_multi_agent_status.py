'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, these tests will check that the status of multiple agents is active after
       sending start-up and keep-alive events to each of them.

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
import pytest

import wazuh_testing.remote as rd
import wazuh_testing.tools.agent_simulator as ag

from time import sleep

from wazuh_testing import TCP, UDP, TCP_UDP
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.thread_executor import ThreadExecutor


# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_multi_agent_status.yaml')

# Set configuration
parameters = [
    {'PROTOCOL': TCP, 'PORT': 1514},
    {'PROTOCOL': TCP, 'PORT': 56000},
    {'PROTOCOL': UDP, 'PORT': 1514},
    {'PROTOCOL': UDP, 'PORT': 56000},
    {'PROTOCOL': TCP_UDP, 'PORT': 1514},
    {'PROTOCOL': TCP_UDP, 'PORT': 56000}
]

metadata = [
    {'protocol': TCP, 'port': 1514},
    {'protocol': TCP, 'port': 56000},
    {'protocol': UDP, 'port': 1514},
    {'protocol': UDP, 'port': 56000},
    {'protocol': TCP_UDP, 'port': 1514},
    {'protocol': TCP_UDP, 'port': 56000}
]

configuration_ids = [f"{item['PROTOCOL'].upper()}_{item['PORT']}" for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def check_active_agents(num_agents=1, manager_address='127.0.0.1', agent_version='4.2.0', agent_os='debian7',
                        manager_port=1514, protocol=TCP):
    """Check if the status of the agents is active after sending start-up and keep-alive events.

    This can be done for n agents using any protocol.

    Args:
        num_agents (int): Number of agents to create and check their status.
        manager_address (str): Manager IP address.
        agent_version (str): Agent wazuh version.
        agent_os (str): Agent operating system.
        manager_port (int): Manager remote communication port.
        protocol (str): It can be TCP, UDP or TCP_UDP (both).

    Raises:
        AttributeError: If the agent status is not active.
    """
    def send_initialization_events(agent, sender):
        """Send the start-up and keep-alive events"""
        try:
            sender.send_event(agent.startup_msg)
            # Wait 1 second between start-up message and keep_alive
            sleep(1)
            sender.send_event(agent.keep_alive_event)
            # Wait 1 seconds to ensure that the message has ben sent before closing the socket.
            sleep(1)
        finally:
            sender.socket.close()

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Create num_agents (parameter) agents
    agents = ag.create_agents(agents_number=num_agents, manager_address=manager_address, disable_all_modules=True,
                              agents_version=[agent_version]*num_agents, agents_os=[agent_os]*num_agents)
    send_event_threads = []

    # Wait until remoted has loaded the new agent key
    rd.wait_to_remoted_key_update(wazuh_log_monitor)

    # Create sender threads. One for each agent
    for idx, agent in enumerate(agents):
        if protocol == TCP_UDP:
            # Round robin to select the protocol
            protocol = TCP if idx % 2 == 0 else UDP

        sender = ag.Sender(manager_address, manager_port, protocol)

        send_event_threads.append(ThreadExecutor(send_initialization_events, {'agent': agent, 'sender': sender}))

    # Run sender threads
    for thread in send_event_threads:
        thread.start()

    # Wait until sender threads finish
    for thread in send_event_threads:
        thread.join()

    # Check agent active status for earch agent
    for agent in agents:
        agent.wait_status_active()


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skip(reason="It requires review and a rework for the agent simulator."
                         "Sometimes it doesn't work properly when it sends keepalives "
                         "messages causing the agent to never being in active status.")
def test_protocols_communication(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check multiple agents status after sending the start-up and keep-alive events via TCP, UDP or both.
                 For this purpose, the test will create all the agents and select the protocol using Round-Robin. Then,
                 every agent uses a sender and it waits until 'active' status appears after an startup and keep-alive
                 events, for each one.
                 It requires review and a rework for the agent simulator. Sometimes it does not work properly when it
                 sends keep-alives messages causing the agent to never being in active status.
    
    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - restart_remoted:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
    
    assertions:
        - Verify that agent status is 'active' after the startup and keep-alive events.
    
    input_description: A configuration template (test_multi_agent_status) is contained in an external YAML file,
                       (wazuh_multi_agent_status.yaml). That template is combined with different test cases defined in
                       the module. Those include configuration settings for the 'wazuh-remoted' daemon and agents info.
                        
    expected_output:
        - agent.status = active
    
    tags:
        - simulator
    '''
    manager_port = get_configuration['metadata']['port']
    protocol = get_configuration['metadata']['protocol']

    check_active_agents(num_agents=2, manager_port=manager_port, protocol=protocol)
