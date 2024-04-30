"""
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when an agent pointing to a master/worker node is registered using CLI tool, and and then
       it's assigned to a new group the change is synced in the cluster.
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
    - https://github.com/wazuh/wazuh-qa/issues/2507
tags:
    - cluster
"""
import os
import time

import pytest

from system.test_cluster.test_agent_groups.common import register_agent
from system import (AGENT_NO_GROUPS, AGENT_STATUS_ACTIVE, AGENT_STATUS_DISCONNECTED, check_agent_groups,
                    check_agent_status, restart_cluster, check_keys_file, assign_agent_to_new_group,
                    delete_agent_group, ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND, create_new_agent_group)
from wazuh_testing.modules import WAZUH_SERVICE_PREFIX, WAZUH_SERVICES_STOPPED
from wazuh_testing.tools.system import HostManager


# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1"]
pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')


# Variables
test_group = 'group_test'
timeout = 40


# Tests
@pytest.mark.parametrize("initial_status", [AGENT_STATUS_ACTIVE, AGENT_STATUS_DISCONNECTED])
@pytest.mark.parametrize("agent_target", ["wazuh-master", "wazuh-worker1"])
def test_assign_agent_to_a_group(agent_target, initial_status, clean_environment):
    '''
    description: Check agent enrollment process and new group assignment works as expected in a cluster environment.
                 Check that when an agent pointing to a master/worker node is registered using CLI tool, and and then
                 it's assigned to a new group the change is synced in the cluster.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_target:
            type: String
            brief: Name of the host where the agent will register.
        - initial_status:
            type: String
            brief: Status of the agent when the assign the new group.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering and before starting the agent, it has no groups assigned.
        - Verify that after registering the agent appears as active/disconnected in all nodes.
        - Verify that after registering and after starting the agent, it has the 'group_test' group assigned.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''
    agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], agent_target, host_manager)
    # Check that agent has no group assigned
    check_agent_groups(agent_id, AGENT_NO_GROUPS, test_infra_managers, host_manager)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    # Start the enrollment process by restarting cluster
    restart_cluster(test_infra_agents, host_manager)

    time.sleep(timeout)

    # Check that agent status is active in cluster
    check_agent_status(agent_id, agent_name, agent_ip, AGENT_STATUS_ACTIVE, host_manager, test_infra_managers)

    if (initial_status == AGENT_STATUS_DISCONNECTED):
        host_manager.control_service(host='wazuh-agent1', service=WAZUH_SERVICE_PREFIX, state=WAZUH_SERVICES_STOPPED)

        time.sleep(timeout)

        check_agent_status(agent_id, agent_name, agent_ip, AGENT_STATUS_DISCONNECTED, host_manager, test_infra_managers)

    try:
        # Create new group
        create_new_agent_group(test_infra_managers[0], test_group, host_manager)

        # Add agent to a new group
        assign_agent_to_new_group('wazuh-master', test_group, agent_id, host_manager)

        time.sleep(timeout)

        # Check that agent has group set to group_test on Managers
        check_agent_groups(agent_id, test_group, test_infra_managers, host_manager)

    finally:
        # Delete group of agent
        delete_agent_group('wazuh-master', test_group, host_manager)
