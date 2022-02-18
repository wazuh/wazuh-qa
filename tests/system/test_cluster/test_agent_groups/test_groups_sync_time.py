'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: This tests check that when a cluster has a series of agents with groups assigned, when an agent has it's
        group changed by a Wazuh-DB command, the cluster updates it's information.
tier: 2
modules:
    - cluster
components:
    - manager
    - agent
daemons:
    - wazuh-db
    - wazuh-clusterd
os_platform:
    - linux
os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
references:
    - https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html
    - https://documentation.wazuh.com/current/user-manual/registering/command-line-registration.html
    - https://documentation.wazuh.com/current/user-manual/registering/agent-enrollment.html
tags:
    - wazuh-db
'''
import os
import time

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.system import HostManager
from system import (create_new_agent_group, check_agent_groups, remove_cluster_agents,
                    clean_cluster_logs, delete_group_of_agents)
from system.test_cluster.test_agent_groups.common import register_agent

# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
agents_in_cluster = 40
test_infra_agents=[]
agent_groups=[]
for x in range(agents_in_cluster): 
    test_infra_agents.append("wazuh-agent" + str(x+1))
    agent_groups.append("Group" + str(x+1))

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'big_cluster_40_agents', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
test_time = 400
sync_delay = 40

@pytest.fixture(scope='function')
def clean_cluster_environment():
    clean_cluster_logs(test_infra_managers + test_infra_agents, host_manager)
    yield
    # Remove the agent once the test has finished
    remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)
    for group in agent_groups:
        delete_group_of_agents(test_infra_managers[0], group, host_manager)


@pytest.mark.parametrize("agent_host", test_infra_managers[0:1])
def test_agent_groups_sync_time(agent_host, clean_cluster_environment):
    '''
    description: Check that after a long time when the manager has been unable to synchronize de databases, because
    new agents are being continually added, database synchronization is forced and the expected information is in
    all nodes after the expected sync time.
    wazuh_min_version: 4.4.0
    parameters:
        - clean_enviroment:
            type: fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering and after starting the agent, the indicated group is synchronized.
    expected_output:
        - The 'Agent_name' with ID 'Agent_id' belongs to groups: 'group_name'.
    '''
    print("Tiempo de Inicio"+str(time.time()))
    # Create all groups
    for group in agent_groups:
        print("--------Creating Group-------" + str(group))
        create_new_agent_group(test_infra_managers[0], group, host_manager)

    # Register agents with their groups in manager    
    agent_data=[]
    for index, agent in enumerate(test_infra_agents):
        print("--------Register Agent-------" + str(agent))
        data = register_agent(agent, agent_host, host_manager, agent_groups[index])
        agent_data.append(data)

    # get the time before all the process is started
    time_before = time.time()
    end_time = time_before + test_time
    active_agent = 0
    while time.time() < end_time:
        if active_agent < agents_in_cluster:
            print("--------ComandTime-------" + str(time.time()) + "-----------------"+ str(active_agent))
            host_manager.run_command(test_infra_agents[active_agent], f'{WAZUH_PATH}/bin/wazuh-control start')
            #host_manager.get_host(test_infra_agents[active_agent]).ansible('command', f'service wazuh-agent restart', check=False)
            active_agent = active_agent +1
    
    assert active_agent == agents_in_cluster, f"Unable to restart all agents in the expected time. Agents restarted: {active_agent}"

    time.sleep(sync_delay)
    
    # Check that agent has the expected group assigned in all nodes
    for index, agent in enumerate(agent_data):
        data = agent_data[index]
        check_agent_groups(data[1], agent_groups[index], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_managers
