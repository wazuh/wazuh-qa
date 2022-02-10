'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: system
brief: 
tier: 0
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
from system import (create_new_agent_group, check_agent_groups, check_agent_status,
                    remove_cluster_agents, restart_cluster, clean_cluster_logs, delete_group_of_agents)
from system.test_cluster.test_agent_groups.common import register_agent

# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_new_nodes = ["wazuh-worker3"]
test_infra_agents = ["wazuh-agent1", "wazuh-agent2", "wazuh-agent3"]
agent_groups = ["Group1", "Group2", "Group3"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'four_manager_disconnected_node', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')


@pytest.fixture(scope='function')
def clean_cluster_environment():
    clean_cluster_logs(test_infra_managers + test_infra_agents + test_infra_new_nodes, host_manager)
    yield
    # Remove the agent once the test has finished
    remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)
    for group in agent_groups:
        delete_group_of_agents(test_infra_managers[0], group, host_manager)
    host_manager.control_service(host=test_infra_new_nodes[0], service='wazuh', state="stopped")


def test_agent_groups_new_cluster_node(clean_cluster_environment):
    '''
    description: Check that having a series of agents assigned with different groups, when an new node is added to
    the cluster, the group data is synchronized to the new node.
    wazuh_min_version: 4.4.0
    parameters:
        - clean_enviroment:
            type: fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering the agents appear as active in all nodes.
        - Verify that after registering and after starting the agent, the indicated group is synchronized.
        - Verify that after after adding a new node to the cluster, the agent's group data is synchronized.
    expected_output:
        - The 'Agent_name' with ID 'Agent_id' belongs to groups: 'group_name'.
    '''
    for group in agent_groups:
        create_new_agent_group(test_infra_managers[0], group, host_manager)

    agent1_data = register_agent(test_infra_agents[0], test_infra_managers[0], host_manager, agent_groups[0])
    agent2_data = register_agent(test_infra_agents[1], test_infra_managers[0], host_manager, agent_groups[1])
    agent3_data = register_agent(test_infra_agents[2], test_infra_managers[0], host_manager, agent_groups[2])
    

    restart_cluster(test_infra_agents, host_manager)
    time.sleep(10)
    # Check that agent status is active in cluster
    check_agent_status(agent1_data[1], agent1_data[2], agent1_data[0], "active", host_manager, test_infra_managers)
    check_agent_status(agent2_data[1], agent2_data[2], agent2_data[0], "active", host_manager, test_infra_managers)
    check_agent_status(agent3_data[1], agent3_data[2], agent3_data[0], "active", host_manager, test_infra_managers)


    # Check that agent has the expected group assigned in all nodes
    check_agent_groups(agent1_data[1], agent_groups[0], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_managers
    check_agent_groups(agent2_data[1], agent_groups[1], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_managers
    check_agent_groups(agent3_data[1], agent_groups[2], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_managers

    restart_cluster(test_infra_new_nodes, host_manager)
    time.sleep(10)

    # Check that agent status is active in new node
    check_agent_status(agent1_data[1], agent1_data[2], agent1_data[0], "active", host_manager, test_infra_new_nodes)
    check_agent_status(agent2_data[1], agent2_data[2], agent2_data[0], "active", host_manager, test_infra_new_nodes)
    check_agent_status(agent3_data[1], agent3_data[2], agent3_data[0], "active", host_manager, test_infra_new_nodes)
    
    # Check that agent has group set to default in new node
    check_agent_groups(agent1_data[1], agent_groups[0], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_new_nodes
    check_agent_groups(agent2_data[1], agent_groups[1], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_new_nodes
    check_agent_groups(agent3_data[1], agent_groups[2], ["wazuh-master"], host_manager) # replace wazuh-master for test_infra_new_nodes