'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
            Created by Wazuh, Inc. <info@wazuh.com>.
            This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Wazuh manager handles agent groups.
        If a group is deleted from a master cluster, there will be an instance where the agents require a
        resynchronization (syncreq).
        If the group is deleted from a worker cluster, the cluster master will take care of reestablishing the
        group structure without the need for resynchronization.
        This test suite tests the correct functioning of the mentioned use case.
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

import json
import os
import pytest
import time
from time import time as current_time
from wazuh_testing import T_025, T_1, T_5, T_10
from wazuh_testing.tools.system import HostManager
from system import (assign_agent_to_new_group, create_new_agent_group, delete_agent_group, execute_wdb_query,
                    restart_cluster)
from wazuh_testing.tools.configuration import get_test_cases_data
from system.test_cluster.test_agent_groups.common import register_agent

pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

test_infra_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2', 'wazuh-agent1', 'wazuh-agent2']
test_infra_managers = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
test_infra_agents = ['wazuh-agent1', 'wazuh-agent2']
groups = ['group_master', 'group_worker1', 'group_worker2']
workers = ['wazuh-worker1', 'wazuh-worker2']
groups_created = []
query = "global 'sql select name, group_sync_status from agent;'"

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
local_path = os.path.dirname(os.path.abspath(__file__))
test_cases_yaml = os.path.join(data_path, 'cases_group_sync.yaml')
wdb_query = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'script/wdb-query.py')
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               '..', '..', 'provisioning', 'enrollment_cluster', 'roles', 'agent-role',
                               'files', 'ossec.conf')
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(test_cases_yaml)
TIMEOUT_SECOND_CHECK = 10

@pytest.fixture()
def group_creation_and_assignation(metadata, target_node):

    agent_ids = []
    for agent in test_infra_agents:
        agent_ip, agent_id, agent_name, manager_ip = register_agent(agent, test_infra_hosts[0], host_manager)
        agent_ids.append(agent_id)

    restart_cluster(test_infra_agents, host_manager)

    time.sleep(T_10)
    for group in groups:
        create_new_agent_group(target_node, group, host_manager)

    if metadata['agent_in_group'] == 'agent1':
        for group in groups:
            assign_agent_to_new_group(target_node, group, agent_ids[0], host_manager)

    elif metadata['agent_in_group'] == 'agent2':
        for group in groups:
            assign_agent_to_new_group(target_node, group, agent_ids[1], host_manager)

    else:
        for group in groups:
            for agent_id in agent_ids:
                assign_agent_to_new_group(target_node, group, agent_id, host_manager)

    yield

    for group in groups:
        delete_agent_group(test_infra_hosts[0], group, host_manager, 'api')


@pytest.fixture()
def wait_end_initial_syncreq():
    timeout = current_time() + T_10
    result = execute_wdb_query(query, test_infra_hosts[0], host_manager)

    while 'syncreq' in result:
        time.sleep(T_1)
        if current_time() >= timeout:
            pytest.fail('Test failure due to unstable environment, syncreq does not disappear after group management')
        result = execute_wdb_query(query, test_infra_hosts[0], host_manager)


@pytest.mark.parametrize('target_node', ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2'])
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
def test_group_sync_status(metadata, target_node, clean_environment, group_creation_and_assignation,
                           wait_end_initial_syncreq):
    '''
    description: Delete a group folder in wazuh server cluster and check group_sync status in 2 times.
    wazuh_min_version: 4.4.0
    metadata:
        - metadata:
            type: list
            brief: List of tests to be performed.
        - target_node:
            type: list
            brief: List of nodes from the groups will be managed.
        - clean_environment:
            type: fixture
            brief: Cleaning logs and resetting environment before testing.
        - group_creation_and_assignation:
            type: fixture
            brief: Delete and create from zero all the groups that are going to be used for testing.
                    It includes group cleaning after tests.
        - wait_end_initial_syncreq:
            type: fixture
            brief: Wait until syncreqs related with the test-environment setting get neutralized
    assertions:
        - Verify that group_sync status changes according the trigger.
        - Verify same conditions creating and assigning groups from all wazuh-manager clusters (Master and Workers)
    input_description: Different use cases are found in the test module and include parameters.
    expected_output:
        - If the group-folder is deleted from master cluster, it is expected to find a
        syncreq group_sync status until it gets synced.
        - If the group-folder is deletef rom a worker cluster, it is expected that master
        cluster recreates groups without syncreq status.
    '''
    # Delete group folder

    delete_agent_group(metadata['delete_target'], metadata['group_folder_deleted'], host_manager, 'folder')

    # Set values
    first_time_check = 'synced'
    second_time_check = ''

    # Check each 0.10 seconds/10 seconds sync_status
    for _ in range(T_10):
        status_info = json.loads(execute_wdb_query(query, test_infra_hosts[0], host_manager))[1:3]
        agent1_status = status_info[0]['group_sync_status']
        agent2_status = status_info[1]['group_sync_status']

        if metadata['agent_in_group'] == 'agent1':
            if agent1_status == 'syncreq' and agent2_status == 'synced':
                first_time_check = "syncreq"
                break

        elif metadata['agent_in_group'] == 'agent2':
            if agent1_status == 'synced' and agent2_status == 'syncreq':
                first_time_check = "syncreq"
                break

        else:
            if agent1_status == 'syncreq' and agent2_status == 'syncreq':
                first_time_check = 'syncreq'
                break

        time.sleep(0.10)

    assert metadata['expected_first_check'] == first_time_check

    time.sleep(TIMEOUT_SECOND_CHECK)

    # Check after 5 seconds, sync_status
    if 'syncreq' in execute_wdb_query(query, test_infra_hosts[0], host_manager):
        second_time_check = 'syncreq'
    else:
        second_time_check = 'synced'

    assert metadata['expected_second_check'] == second_time_check
