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
from system import (ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND, check_agent_groups, check_keys_file,
                    create_new_agent_group, delete_agent_group, remove_cluster_agents,
                    assign_agent_to_new_group, restart_cluster)
from wazuh_testing import T_10, T_20
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.file import replace_regex_in_file
from wazuh_testing.tools.system_monitoring import HostMonitor
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS


pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

# Hosts
test_infra_managers = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
test_infra_agents = ['wazuh-agent1', 'wazuh-agent2']

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
master_messages_path = os.path.join(data_path, 'guess_group_messages_master.yaml')
worker_messages_path = os.path.join(data_path, 'guess_group_messages_worker.yaml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')


# Variables
group_id = 'group_test'
multigroups_id = 'default,group_test'


# Fixtures
@pytest.fixture()
def modify_local_internal_options(status_guess_agent_group):
    """Fixture to configure the local internal options file.

    It uses the variable local_internal_options. This should be
    a dictionary wich keys and values corresponds to the internal option configuration and host to apply, For example:
    local_internal_options = {'wazuh-master': [{'name': 'remoted.guess_agent_group', 'value': '0'}],
                              'wazuh-worker1': [{'name': 'remoted.debug', 'value': '2'}, {'name': 'authd.debug',
                                                                                          'value': '2'}]}
    """
    local_internal_options = {test_infra_managers[0]: [{'name': 'remoted.guess_agent_group', 'value':
                                                        f"{status_guess_agent_group}"}]}

    # Get previous local internal options
    backup_local_internal_options = host_manager.get_file_content(test_infra_managers[0], WAZUH_LOCAL_INTERNAL_OPTIONS)

    # Add local internal options
    host_manager.configure_local_internal_options(local_internal_options)

    yield

    # Restore local internal options
    host_manager.modify_file_content(test_infra_managers[0], WAZUH_LOCAL_INTERNAL_OPTIONS,
                                     backup_local_internal_options)


# Tests
@pytest.mark.parametrize('status_guess_agent_group', ['0', '1'])
@pytest.mark.parametrize('target_node', ['wazuh-master', 'wazuh-worker1'])
def test_guess_single_group(target_node, status_guess_agent_group, clean_environment, modify_local_internal_options):
    '''
    description: Check that when an agent registered in the manager and assigned to group is removed, performs a
                 guessing operation and determinates the groups to with the agent was assigned.
    wazuh_min_version: 4.4.0
    parameters:
        - target_node:
            type: String
            brief: Name of the host where the agent will register.
        - status_guess_agent_group
            type: String
            brief: Determine if the group guessing mechanism is enabled or disabled.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
        - modify_internal_options:
            type: Fixture
            brief: Add internal options in local_internal_options.conf
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering the agent appears as never_connected in all nodes.
        - Verify that after registering it has the 'Null' group assigned.
        - Verify that after assign group with agent-groups the change is sync with the cluster.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''
    # Restart master to apply local internal options
    restart_cluster([test_infra_managers[0]], host_manager)
    time.sleep(T_20)

    # Create new group
    create_new_agent_group(test_infra_managers[0], group_id, host_manager)

    # Register agent with agent-auth
    agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], target_node,
                                                                host_manager)
    # Restart agent
    restart_cluster([test_infra_agents[0]], host_manager)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    try:
        # Assign agent to group
        assign_agent_to_new_group(test_infra_managers[0], group_id, agent_id, host_manager)

        # Remove agent from default to test single group guess (not multigroup)
        host_manager.run_command(test_infra_managers[0], f"/var/ossec/bin/agent_groups -q -r -i {agent_id} -g default")

        time.sleep(T_20)

        # Check that agent has group set to group_test on Managers
        check_agent_groups(agent_id, group_id, test_infra_managers, host_manager)

        # Remove the agent
        remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)

        # Register agent with agent-auth
        agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], target_node,
                                                                    host_manager)

        # Check that agent has client key file
        assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

        # Restart agent
        restart_cluster([test_infra_agents[0]], host_manager)
        time.sleep(T_20)

        # Check if remoted.guess_agent_group is disabled
        expected_group = 'default' if int(status_guess_agent_group) == 0 else group_id

        # Run the callback checks for the ossec.log
        messages_path = master_messages_path if target_node == 'wazuh-master' else worker_messages_path
        replace_regex_in_file(['AGENT_ID', 'GROUP_ID'], [agent_id, expected_group], messages_path)
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path,
                    tmp_path=tmp_path).run(update_position=True)

        check_agent_groups(agent_id, expected_group, test_infra_managers, host_manager)

    finally:
        # Delete group of agent
        delete_agent_group(test_infra_managers[0], group_id, host_manager)
        replace_regex_in_file([agent_id, expected_group], ['AGENT_ID', 'GROUP_ID'], messages_path)


@pytest.mark.parametrize('n_agents', [1, 2])
@pytest.mark.parametrize('status_guess_agent_group', ['0', '1'])
@pytest.mark.parametrize('target_node', ['wazuh-master', 'wazuh-worker1'])
def test_guess_multigroups(n_agents, target_node, status_guess_agent_group, clean_environment,
                           modify_local_internal_options):
    '''
    description: Check that when an agent registered in the manager and assigned to group is removed, performs a
                 guessing operation and determinates the groups to with the agent was assigned.
    wazuh_min_version: 4.4.0
    parameters:
        - n_agents:
            type: Int
            brief: Number of agents to register.
        - target_node:
            type: String
            brief: Name of the host where the agent will register.
        - status_guess_agent_group
            type: String
            brief: Determine if the group guessing mechanism is enabled or disabled.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
        - modify_internal_options:
            type: Fixture
            brief: Add internal options in local_internal_options.conf
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering the agent appears as never_connected in all nodes.
        - Verify that after registering it has the 'Null' group assigned.
        - Verify that after assign group with agent-groups the change is sync with the cluster.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''
    # Restart master to apply local internal options
    restart_cluster([test_infra_managers[0]], host_manager)
    time.sleep(T_20)

    # Create new group
    create_new_agent_group(test_infra_managers[0], group_id, host_manager)

    # Register agent with agent-auth
    agents_data = []
    for agent in range(n_agents):
        agent_data = register_agent(test_infra_agents[agent], target_node, host_manager)
        agents_data.append(agent_data)

    # Restart agent
    restart_cluster(test_infra_agents, host_manager)
    time.sleep(T_10)

    # Check that agent has client key file
    for agent in range(n_agents):
        assert check_keys_file(test_infra_agents[agent], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    try:
        # Create new group and assing agent
        for agent in range(n_agents):
            assign_agent_to_new_group(test_infra_managers[0], group_id, agents_data[agent][1], host_manager)
        time.sleep(T_20)

        # Check that agent has group set to group_test on Managers
        for agent in range(n_agents):
            check_agent_groups(agents_data[agent][1], group_id, test_infra_managers, host_manager)

        # Remove the agent
        remove_cluster_agents(test_infra_managers[0], [test_infra_agents[0]], host_manager, [agents_data[0][1]])

        # Register agent again with agent-auth
        agent1_ip, agent1_id, agent1_name, ag1_manager_ip = register_agent(test_infra_agents[0], target_node,
                                                                           host_manager)

        # Check that agent has client key file
        assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

        # Restart agent
        restart_cluster([test_infra_agents[0]], host_manager)
        time.sleep(T_20)

        # Check if remoted.guess_agent_group is disabled
        expected_group = 'default' if int(status_guess_agent_group) == 0 or n_agents == 1 else multigroups_id

        # Run the callback checks for the ossec.log
        messages_path = master_messages_path if target_node == 'wazuh-master' else worker_messages_path
        replace_regex_in_file(['AGENT_ID', 'GROUP_ID'], [agent1_id, expected_group], messages_path)

        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path,
                    tmp_path=tmp_path).run(update_position=True)

        for group in expected_group.split(','):
            check_agent_groups(agent1_id, group, test_infra_managers, host_manager)

    finally:
        # Delete group of agent
        delete_agent_group(test_infra_managers[0], group_id, host_manager)
        replace_regex_in_file([agent1_id, expected_group], ['AGENT_ID', 'GROUP_ID'], messages_path)
