# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from time import sleep

import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import TCP, UDP
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks

pytestmark = pytest.mark.tier(level=2)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agents_reconnection.yaml')
disconnect_time = 5

parameters = [
    {'PORT': 1514, 'TIME': f"{disconnect_time}s"},
    {'PORT': 56000, 'TIME': f"{disconnect_time}s"},
]

metadata = [
    {'port': 1514, 'time': f"{disconnect_time}s"},
    {'port': 56000, 'time': f"{disconnect_time}s"},
]

agent_info = {
    'manager_address': '127.0.0.1',
    'agents_os': 'debian7',
    'agents_version': '4.2.0'
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [f"{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def connect_and_check_agents_status(agents, agents_connections, port, use_tcp):
    """Connect a list of agents changing the protocol used and checks their status

    Args:
        agents (list): list containing the agents.
        agents_connections (dict): dictionary used to store the agents.
        port (int): port used to connect the agent.
        use_tcp (bool): variable used to alternate between protocols.
    """
    for agent in agents:
        sender, injector = ag.connect(agent, protocol=TCP if use_tcp else UDP, port=port)
        agents_connections[agent.id] = {'agent': agent, 'sender': sender, 'injector': injector}
        use_tcp = not use_tcp
        assert agent.get_connection_status() == 'active'


def stop_all(connections):
    """Stop all active agents

    Args:
        connections (dict): contains the agents, the injectors and the senders for each agent.
    """
    for agent in connections:
        connections[agent]['injector'].stop_receive()


def test_agents_switching_protocols(get_configuration, configure_environment, restart_remoted):
    """Checks if the agents can reconnect without issues to the manager after switching their protocol"""

    port = get_configuration['metadata']['port']
    use_tcp, num_agents = False, 2
    agents = ag.create_agents(agents_number=num_agents, manager_address='localhost',
                              agents_os=['debian7']*num_agents)
    agents_connections = {}
    try:
        connect_and_check_agents_status(agents, agents_connections, port, use_tcp)

        stop_all(agents_connections)

        # The test must wait until the manager considers the agents as disconnected. This time is
        # set using the `agents_disconnection_time` option from the `global` section of the conf.
        sleep(disconnect_time*2)

        connect_and_check_agents_status(agents, agents_connections, port, not use_tcp)

    finally:
        stop_all(agents_connections)
