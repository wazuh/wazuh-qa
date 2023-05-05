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

import os
import pytest
import time
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.file import read_file, read_yaml
from wazuh_testing.tools.system import HostManager
from system import (get_agent_id, assign_agent_to_new_group, create_new_agent_group, 
                            delete_agent_group, execute_wdb_query, restart_cluster)
from wazuh_testing import T_10, T_20

from system.test_cluster.test_agent_groups.common import register_agent

pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

testinfra_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2', 'wazuh-agent1', 'wazuh-agent2']
groups = ['group_master', 'group_worker1', 'group_worker2']
agents = ['wazuh-agent1', 'wazuh-agent2']
workers = ['wazuh-worker1', 'wazuh-worker2']
groups_created = []

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/cases_group_sync.yml'))
wdb_query = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'script/wdb-query.py')
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               '..', '..', 'provisioning', 'enrollment_cluster', 'roles', 'agent-role', 
                               'files', 'ossec.conf')

@pytest.fixture
def agent_configuration():
    restart_cluster(workers, host_manager)

@pytest.fixture
def group_creation_and_assignation():
    for group in groups:
        create_new_agent_group(testinfra_hosts[0], group, host_manager)
    
    agent_ids = get_agent_id(host_manager).split()
    for group in groups:
        for agent_id in agent_ids:
            assign_agent_to_new_group(testinfra_hosts[0], group, agent_id, host_manager)
    
    yield
    for group in groups:
        delete_agent_group(testinfra_hosts[0], group, host_manager, 'api')

@pytest.fixture
def delete_group_folder(test_case):
    host_manager.run_command(test_case['test_case']['host'], 
                             f"rm -r {WAZUH_PATH}/etc/shared/{test_case['test_case']['group_deleted']} -f") 

@pytest.fixture
def wait_end_initial_syncreq():
    query = "global 'sql select group_sync_status from agent;'"
    result = execute_wdb_query(query, testinfra_hosts[0], host_manager)
    while 'syncreq' in result:
        time.sleep(1)
        result = execute_wdb_query(query, testinfra_hosts[0], host_manager)

@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])

def test_group_sync_status(test_case, agent_configuration, group_creation_and_assignation, 
                           wait_end_initial_syncreq, delete_group_folder):

    '''
    description: Delete a group folder in wazuh server cluster and check group_sync status in 2 times.
    wazuh_min_version: 4.4.0
    parameters:
        - test_case:
            type: list
            brief: List of tests to be performed.     
        - agent_configuration:
            type: fixture
            brief: Restarting agents to be included in the network.     
        - group_creation_and_assignation:
            type: fixture
            brief: Delete and create from zero all the groups that are going to be used for testing.
                    It includes group cleaning after tests.
        - wait_end_initial_syncreq:
            type: fixture
            brief: Wait until syncreqs related with the test-environment setting get neutralized
        - delete_group_folder:
            type: fixture
            brief: Delete the folder-group assigned by test case (trigger)

    assertions:
        - Verify that group_sync status changes according the trigger.
        
    input_description: Different use cases are found in the test module and include parameters.
    
    expected_output:
        - If the group-folder is deleted from master cluster, it is expected to find a 
        syncreq group_sync status until it gets synced.
        - If the group-folder is deletef rom a worker cluster, it is expected that master 
        cluster recreates groups without syncreq status.
    '''
    #Checks
    query = "global 'sql select group_sync_status from agent;'"

    first_time_check = "synced"
    second_time_check = "synced"
    
    for i in range(T_20):
        time.sleep(0.25)
        result = execute_wdb_query(query, testinfra_hosts[0], host_manager)
        if 'syncreq' in result:
            first_time_check = "syncreq"

    time.sleep(T_10)

    result = execute_wdb_query(query, testinfra_hosts[0], host_manager)
    if 'syncreq' in result:
        second_time_check = "syncreq"   
        
    #Results
    assert test_case['test_case']['first_time_check'] == first_time_check 
    assert test_case['test_case']['second_time_check'] == second_time_check  
