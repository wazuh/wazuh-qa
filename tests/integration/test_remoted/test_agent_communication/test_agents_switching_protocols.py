# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from time import sleep

import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import TCP, UDP, TCP_UDP
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks

pytestmark = pytest.mark.tier(level=2)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_protocols_communication.yaml')

parameters = [
    {'PROTOCOL': TCP_UDP, 'PORT': 1514},
    # {'PROTOCOL': TCP_UDP, 'PORT': 56000},
]

metadata = [
    {'protocol': TCP_UDP, 'port': 1514},
    # {'protocol': TCP_UDP, 'port': 56000},
]

agent_info = {
    'manager_address': '127.0.0.1',
    'agents_os': 'debian7',
    'agents_version': '4.2.0'
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [f"{x['PROTOCOL']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_agents_switching_protocols(get_configuration, configure_environment, restart_remoted):
    """Checks if the agents can reconnect without issues to the manager after switching their protocol"""

    port = get_configuration['metadata']['port']
    agents, use_tcp, num_agents = {}, False, 2

    for agent in ag.create_agents(agents_number=num_agents, manager_address='localhost',
                                  agents_os=['debian7']*num_agents):
        print(f"Agent {agent.id} will connect using {TCP if use_tcp else UDP}")
        sender, injector = ag.connect(agent, protocol=TCP if use_tcp else UDP, port=port)
        agents[agent.id] = {'agent': agent, 'sender': sender, 'injector': injector}
        use_tcp = not use_tcp
        assert agent.get_connection_status() == 'active'

    for agent in agents:
        agents[agent]['injector'].stop_receive()

    sleep(50)

    for agent_id in agents:
        use_tcp = not use_tcp
        agent = agents[agent_id]['agent']
        print(f"Agent {agent_id} will connect using {TCP if use_tcp else UDP}")
        sender, injector = ag.connect(agent, protocol=TCP if use_tcp else UDP, port=port)
        agents[agent_id] = {'agent': agent, 'sender': sender, 'injector': injector}
        assert agent.get_connection_status() == 'active'
