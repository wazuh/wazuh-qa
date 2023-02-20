"""
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when an agent with status never_connected, pointing to a master/worker node is
       registered using agent-auth and when it is assigned to a group with agent-group, the change is
       synced in the cluster.
tier: 1
modules:
    - cluster
components:
    - manager
    - agent
path: /tests/system/test_cluster/test_agent_groups/test_assign_agent_to_a_group_by_tool.py
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
    - https://github.com/wazuh/wazuh-qa/issues/2513
tags:
    - cluster
"""
import os
import time

import pytest

from system.test_cluster.test_agent_groups.common import register_agent
from system import (check_agent_groups, check_agent_status, check_keys_file, delete_group_of_agents,
                    assign_agent_to_new_group, AGENT_NO_GROUPS, AGENT_STATUS_NEVER_CONNECTED)
from wazuh_testing.tools.system import HostManager


pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')
group_id = 'group_test'
wait_time = 10


# Tests
@pytest.mark.parametrize("agent_target", ['wazuh-master', 'wazuh-worker1'])
def test_assign_agent_to_a_group_by_tool(agent_target, clean_environment):
    '''
    description: Check that when an agent with status never_connected, pointing to a master/worker node is
                 registered using agent-auth and when it is assigned to a group with agent-group, the change is synced
                 with the cluster.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_target:
            type: string
            brief: name of the host where the agent will register
        - clean_enviroment:
            type: fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering the agent appears as never_connected in all nodes.
        - Verify that after registering it has the 'Null' group assigned.
        - Verify that after assign group with agent-groups the change is sync with the cluster.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''

    # Register agent with agent-auth
    agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], agent_target,
                                                                host_manager)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager)

    # Check that agent status is never_connected in cluster
    check_agent_status(agent_id, agent_name, agent_ip, AGENT_STATUS_NEVER_CONNECTED, host_manager, test_infra_managers)

    # Check that agent has group set to Null on Managers
    check_agent_groups(agent_id, AGENT_NO_GROUPS, test_infra_managers, host_manager)

    try:
        # Add group to agent1
        assign_agent_to_new_group(test_infra_managers[0], group_id, agent_id, host_manager)

        time.sleep(wait_time)
        # Check that agent has group set to group_test on Managers
        check_agent_groups(agent_id, group_id, test_infra_managers, host_manager)

    finally:
        # Delete group of agent
        delete_group_of_agents(test_infra_managers[0], group_id, host_manager)
