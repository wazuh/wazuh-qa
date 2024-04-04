'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: sys
tier: 0
modules:
    - enrollment
components:
    - manager
    - agent
daemons:
    - wazuh-authd
    - wazuh-agentd
os_platform:
    - linux
os_version:
    - Debian Buster
references:
    - https://documentation.wazuh.com/current/user-manual/registering/agent-enrollment.html
'''

import os
import pytest
import re
import time
import threading
from wazuh_testing import T_1
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.system import HostManager
from system import restart_cluster

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'big_cluster_40_agents', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                               'provisioning', 'big_cluster_40_agents', 'roles', 'agent-role', 'files', 'ossec.conf')

testinfra_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
workers = ['wazuh-worker1', 'wazuh-worker2']
agents = []

TIMEOUT_AGENT = 8

number_agents = 40
for number_agent in range(number_agents):
    agents.append(f'wazuh-agent{number_agent+1}')

pytestmark = [pytest.mark.cluster, pytest.mark.big_cluster_40_agents_env]

@pytest.fixture()
def restart_all_agents():
    restart_cluster(agents, host_manager, parallel=True)
    time.sleep(T_1)

    yield

    restart_cluster(testinfra_hosts + agents, host_manager, parallel=True)


@pytest.fixture()
def stop_gracefully_all_agents():
    threads = []
    for agent in agents:
        thread = threading.Thread(target=host_manager.run_command, args=(agent, f'{WAZUH_PATH}/bin/wazuh-control stop',))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def test_shut_down_message_gracefully_stopped_agent(restart_all_agents, stop_gracefully_all_agents):
    '''
        description: Checking shutdown message when socket is closed.
        wazuh_min_version: 4.6.0
        parameters:
            - restart_all_agents:
                type: function
                brief: Restart all the agents to manipulate them after.
            - stop_gracefully_all_agents:
                type: function
                brief: Stop agents gracefully
        assertions:
            - Verify that all agents status became 'Disconnected' after gracefully shutdown.

        input_description: Different use cases are found in the test module and include parameters.

        expected_output:
            - Gracefully closed, it is expected to find agents 'Disconected' in agent-manager
    '''
    time.sleep(TIMEOUT_AGENT)

    matches = re.findall(r"Disconnected", host_manager.run_command(testinfra_hosts[0],
                                                                   f'{WAZUH_PATH}/bin/agent_control -l'))

    assert len(matches) == number_agents
