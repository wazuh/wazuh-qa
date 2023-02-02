"""
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when an agent with status never_connected, pointing to a master/worker node is
       registered using agent-auth with a group the change is sync with the cluster.
tier: 0
modules:
    - cluster
components:
    - manager
    - agent
path: /tests/system/test_cluster/test_agent_groups/test_assign_agent_never_connected_to_group.py
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
    - https://github.com/wazuh/wazuh-qa/issues/2508
tags:
    - cluster
"""
import os
import pytest

from system.test_cluster.test_agent_groups.common import register_agent
from system import (check_agent_groups, check_agent_status, check_keys_file, delete_group_of_agents,
                    AGENT_STATUS_NEVER_CONNECTED, ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND)
from wazuh_testing.tools.system import HostManager


# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1"]
pytestmark = [pytest.mark.cluster]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')
id_group = 'group_test'


# Tests
@pytest.mark.parametrize("test_infra_managers", [test_infra_managers])
@pytest.mark.parametrize("test_infra_agents", [test_infra_agents])
@pytest.mark.parametrize("host_manager", [host_manager])
@pytest.mark.parametrize("agent_target", ['wazuh-master', 'wazuh-worker1'])
def test_assign_agent_to_a_group(agent_target, clean_environment, test_infra_managers, test_infra_agents, host_manager):
    '''
    description: Check that when an agent with status never_connected, pointing to a master/worker node is
                 registered using agent-auth with a group the change is sync with the cluster.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_target:
            type: String
            brief: Name of the host where the agent will register.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
        - test_infra_managers
            type: List
            brief: List of manager hosts in enviroment.
        - test_infra_agents
            type: List
            brief: List of agent hosts in enviroment.
        - host_manager
            type: HostManager object
            brief: Handles connection the enviroment's hosts.
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering the agent appears as never_connected in all nodes.
        - Verify that after registering it has the 'group_test' group assigned.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''

    try:
        # Create group with agent_groups
        host_manager.run_command(test_infra_managers[0], f"/var/ossec/bin/agent_groups -q -a -g {id_group}")

        # Register agent with agent-auth
        agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], agent_target,
                                                                    host_manager, id_group)

        # Check that agent status is never_connected in cluster
        check_agent_status(agent_id, agent_name, agent_ip, AGENT_STATUS_NEVER_CONNECTED,
                           host_manager, test_infra_managers)

        # Check that agent has group set to group_test on Managers
        check_agent_groups(agent_id, id_group, test_infra_managers, host_manager)

        # Check that agent has client key file
        assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    finally:
        # Delete group of agent
        delete_group_of_agents('wazuh-master', id_group, host_manager)
