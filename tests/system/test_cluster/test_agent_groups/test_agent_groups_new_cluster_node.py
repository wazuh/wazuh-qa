'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: system
brief: This tests check that when a cluster has a series of agents with groups assigned, when a new node is
       added to the cluster, that new node the agent's status and groups are synchronized.
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

from wazuh_testing.tools.system import HostManager
from system import (create_new_agent_group, check_agent_groups, check_agents_status_in_node,
                    restart_cluster, AGENT_STATUS_ACTIVE)
from system.test_cluster.test_agent_groups.common import register_agent

# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_new_nodes = ["wazuh-worker3"]
test_infra_agents = ["wazuh-agent1", "wazuh-agent2", "wazuh-agent3"]
agent_groups = ["Group1", "Group2", "Group3"]
pytestmark = [pytest.mark.cluster, pytest.mark.four_manager_disconnected_node_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'four_manager_disconnected_node', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
timeout = 10


# Tests
def test_agent_groups_sync_when_add_a_new_cluster_node(clean_environment):
    '''
    description: Check that having a series of agents assigned with different groups, when an new node is added to
    the cluster, the group data is synchronized to the new node.
    wazuh_min_version: 4.4.0
    parameters:
        - clean_enviroment:
            type: Fixture
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

    agent_status_list = [f"{agent1_data[1]}  {agent1_data[2]}  {agent1_data[0]}  {AGENT_STATUS_ACTIVE}",
                         f"{agent2_data[1]}  {agent2_data[2]}  {agent2_data[0]}  {AGENT_STATUS_ACTIVE}",
                         f"{agent3_data[1]}  {agent3_data[2]}  {agent3_data[0]}  {AGENT_STATUS_ACTIVE}"]
    restart_cluster(test_infra_agents, host_manager)

    # Check that agent status is active in cluster
    for host in test_infra_managers:
        check_agents_status_in_node(agent_status_list, host, host_manager)

    # Check that agent has the expected group assigned in all nodes
    check_agent_groups(agent1_data[1], agent_groups[0], test_infra_managers, host_manager)
    check_agent_groups(agent2_data[1], agent_groups[1], test_infra_managers, host_manager)
    check_agent_groups(agent3_data[1], agent_groups[2], test_infra_managers, host_manager)

    restart_cluster(test_infra_new_nodes, host_manager)

    # Check that agent status is active in new node
    check_agents_status_in_node(agent_status_list, test_infra_new_nodes[0], host_manager)

    # Check that agent has the correct group set in new node
    check_agent_groups(agent1_data[1], agent_groups[0], test_infra_new_nodes, host_manager)
    check_agent_groups(agent2_data[1], agent_groups[1], test_infra_new_nodes, host_manager)
    check_agent_groups(agent3_data[1], agent_groups[2], test_infra_new_nodes, host_manager)


def test_agent_groups_sync_worker_new_node(clean_environment):
    '''
    description: Having two agents assigned to different workers and different groups, check that when an new node
    is added to the cluster, the group data is synchronized to the new node.
    wazuh_min_version: 4.4.0
    parameters:
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering the agents appear as active in all nodes.
        - Verify that after registering and after starting the agent, the indicated group is synchronized.
        - Verify that after after adding a new node to the cluster, the agent's group data is synchronized.
    expected_output:
        - The 'Agent_name' with ID 'Agent_id' belongs to groups: 'group_name'.
    '''
    for group in ["Group1", "Group2"]:
        create_new_agent_group(test_infra_managers[0], group, host_manager)

    agent1_data = register_agent(test_infra_agents[0], test_infra_managers[1], host_manager, agent_groups[0])
    agent2_data = register_agent(test_infra_agents[1], test_infra_managers[2], host_manager, agent_groups[1])

    agent_status_list = [f"{agent1_data[1]}  {agent1_data[2]}  {agent1_data[0]}  {AGENT_STATUS_ACTIVE}",
                         f"{agent2_data[1]}  {agent2_data[2]}  {agent2_data[0]}  {AGENT_STATUS_ACTIVE}"]

    restart_cluster(test_infra_agents[0:2], host_manager)

    # Check that agent status is active in cluster
    for host in test_infra_managers:
        check_agents_status_in_node(agent_status_list, host, host_manager)

    # Check that agent has the expected group assigned in all nodes
    check_agent_groups(agent1_data[1], agent_groups[0], test_infra_managers, host_manager)
    check_agent_groups(agent2_data[1], agent_groups[1], test_infra_managers, host_manager)

    restart_cluster(test_infra_new_nodes, host_manager)
    time.sleep(timeout)

    # Check that agent status is active in new node
    check_agents_status_in_node(agent_status_list, test_infra_new_nodes[0], host_manager)

    # Check that agent has the correct group set in new node
    check_agent_groups(agent1_data[1], agent_groups[0], test_infra_new_nodes, host_manager)
    check_agent_groups(agent2_data[1], agent_groups[1], test_infra_new_nodes, host_manager)
