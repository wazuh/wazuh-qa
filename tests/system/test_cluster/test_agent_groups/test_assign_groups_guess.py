"""
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when an agent registered inthe manager and assigned to group is removed, performs a
       guessing operation and determinates the groups to with the agent was assigned.
tier: 1
modules:
    - cluster
components:
    - manager
    - agent
path: /tests/system/test_cluster/test_agent_groups/test_assign_groups_guess.py
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
from system import (ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND, check_agent_groups,
                    check_keys_file, delete_group_of_agents, remove_cluster_agents,
                    assign_agent_to_new_group, restart_cluster)
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.file import replace_regex_in_file
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools import WAZUH_PATH


# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1"]
pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
master_messages_path = os.path.join(data_path, 'guess_group_messages_master.yaml')
worker_messages_path = os.path.join(data_path, 'guess_group_messages_worker.yaml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')


# Variables
remoted_guess_agent_groups = 'remoted.guess_agent_group='
# this timeout is temporality, this test will be update
timeout = 20


# Tests
@pytest.mark.parametrize("status_guess_agent_group", ['0', '1'])
@pytest.mark.parametrize("agent_target", ['wazuh-master', 'wazuh-worker1'])
def test_assign_agent_to_a_group(agent_target, status_guess_agent_group, clean_environment):
    '''
    description: Check that when an agent registered in the manager and assigned to group is removed, performs a
                 guessing operation and determinates the groups to with the agent was assigned.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_target:
            type: String
            brief: Name of the host where the agent will register.
        - status_guess_agent_group
            type: String
            brief: Determine if the group guessing mechanism is enabled or disabled.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering the agent appears as never_connected in all nodes.
        - Verify that after registering it has the 'Null' group assigned.
        - Verify that after assign group with agent-groups the change is sync with the cluster.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''
    group_id = 'group_test'
    # Modify local_internal_options
    replace = '\n' + remoted_guess_agent_groups + f'{status_guess_agent_group}\n'

    for host in test_infra_managers:
        host_manager.add_block_to_file(host, path=f"{WAZUH_PATH}/etc/local_internal_options.conf",
                                       after="upgrades.", before="authd.debug=2", replace=replace)
    # Restart managers
    restart_cluster(test_infra_managers, host_manager)
    time.sleep(timeout)

    # Register agent with agent-auth
    agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], agent_target,
                                                                host_manager)
    # Restart agent
    restart_cluster(test_infra_agents, host_manager)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    try:
        # Create new group and assing agent
        assign_agent_to_new_group(test_infra_managers[0], group_id, agent_id, host_manager)

        # Remove agent from default to test single group guess (not multigroup)
        host_manager.run_command(test_infra_managers[0], f"/var/ossec/bin/agent_groups -q -r -i {agent_id} -g default")

        time.sleep(timeout)

        # Check that agent has group set to group_test on Managers
        check_agent_groups(agent_id, group_id, test_infra_managers, host_manager)

        # Remove the agent
        remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)

        # Register agent with agent-auth
        agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], agent_target,
                                                                    host_manager)

        # Check that agent has client key file
        assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

        # Restart agent
        restart_cluster(test_infra_agents, host_manager)
        time.sleep(timeout)

        # Check if remoted.guess_agent_group is disabled
        group_id = 'default' if int(status_guess_agent_group) == 0 else group_id

        # Run the callback checks for the ossec.log
        messages_path = master_messages_path if agent_target == 'wazuh-master' else worker_messages_path

        replace_regex_in_file(['AGENT_ID', 'GROUP_ID'], [agent_id, group_id], messages_path)
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path,
                    tmp_path=tmp_path).run(update_position=True)
        check_agent_groups(agent_id, group_id, test_infra_managers, host_manager)

    finally:
        # Delete group of agent
        delete_group_of_agents(test_infra_managers[0], group_id, host_manager)
        replace_regex_in_file([agent_id, group_id], ['AGENT_ID', 'GROUP_ID'], messages_path)
