'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, these tests will check that the manager communicates with several agents
       simultaneously with different protocols.

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
import wazuh_testing.tools.monitoring as mo

from time import sleep
from wazuh_testing import TCP, UDP, TCP_UDP
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.thread_executor import ThreadExecutor



# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_multi_agent_protocols_communication.yaml')

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

agent_info = {
    'manager_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configuration_ids = [f"{item['PROTOCOL'].upper()}_{item['PORT']}" for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def validate_agent_manager_protocol_communication(num_agents=2, manager_port=1514, protocol=TCP):
    """Check the communication between the manager and several agents using different protocols and ports.

    Args:
        num_agents (int): Number of agents to send events and to validate the communication.
        manager_port (int): Manager remote communication port.
        protocol (str): It can be TCP, UDP or TCP_UDP (both).

    Raises:
        TimeoutError: If the event has not been found in the queue socket after the agents have been sent.
    """
    def send_event(event, protocol, manager_port, agent):
        """Send an event to the manager"""
        sender = ag.Sender(agent_info['manager_address'], protocol=protocol, manager_port=manager_port)
        injector = ag.Injector(sender=sender, agent=agent)
        injector.sender.send_event(event)
        return injector


    send_event_threads = []
    search_patterns = []

    # Create num_agents (parameter) agents
    agents = ag.create_agents(agents_number=num_agents, manager_address=agent_info['manager_address'],
                              agents_version=[agent_info['version']]*num_agents,
                              agents_os=[agent_info['os']]*num_agents,
                              disable_all_modules=agent_info['disable_all_modules'])

    for idx, agent in enumerate(agents):
        if protocol == TCP_UDP:
            # Round robin to select the protocol
            protocol = TCP if idx % 2 == 0 else UDP

        # Generate custom events for each agent
        search_pattern = f"test message from agent {agent.id}"
        agent_custom_message = f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: {search_pattern}"
        event = agent.create_event(agent_custom_message)

        # Save the search pattern to check it later
        search_patterns.append(search_pattern)

        # Create sender event threads
        send_event_threads.append(ThreadExecutor(send_event, {'event': event, 'protocol': protocol,
                                                              'manager_port': manager_port, 'agent': agent}))

    # Create archives log monitor
    archives_monitor = rd.create_archives_log_monitor()

    # Wait 10 seconds until remoted is fully initialized
    sleep(10)

    # Start sender event threads
    for thread in send_event_threads:
        thread.start()

    # Wait until sender event threads finish
    for thread in send_event_threads:
        thread.join()

    # Monitor archives log to find the sent messages
    for search_pattern in search_patterns:
        rd.detect_archives_log_event(archives_monitor,
                                     callback=mo.make_callback(pattern=search_pattern, prefix=r".*"),
                                     update_position=False,
                                     timeout=30,
                                     error_message="Agent message wasn't received or took too much time.")


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_multi_agents_protocols_communication(get_configuration, configure_environment, restart_wazuh):
    '''
    description: Check agent-manager communication with several agents simultaneously via TCP, UDP or both.
                 For this purpose, the test will create all the agents and select the protocol using Round-Robin. Then,
                 an event and a message will be created for each agent created. Finally, it will search for
                 those events within the messages sent to the manager.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - restart_wazuh:
            type: fixture
            brief: Stop Wazuh, reset ossec.log and start a new monitor. Then start Wazuh.

    assertions:
        - Verify that the custom events created has been logged correctly.

    input_description: A configuration template (test_multi_agent_protocols_communication) is contained in an external
                       YAML file, (wazuh_multi_agent_protocols_communication.yaml). That template is combined with
                       different test cases defined in the module. Those include configuration settings for the
                       'wazuh-remoted' daemon and agents info.

    expected_output:
        - r".* test message from agent .*"
        - Agent message was not received or took too much time.

    tags:
        - simulator
        - remoted
    '''
    manager_port = get_configuration['metadata']['port']
    protocol = get_configuration['metadata']['protocol']

    validate_agent_manager_protocol_communication(manager_port=manager_port, protocol=protocol)
