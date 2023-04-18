'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Wazuh manager handles agent groups. 
       If a group is deleted from a master cluster, there will be an instance where the agents require a resynchronization (syncreq). 
       If the group is deleted from a worker cluster, the cluster master will take care of reestablishing the group structure without the need for resynchronization.
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
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.file import read_file, read_yaml
from wazuh_testing.tools.system import HostManager
from system import clean_cluster_logs

pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

testinfra_hosts = ['wazuh-master', 'wazuh-worker1','wazuh-worker2']
groups = ['group_master', 'group_worker1', 'group_worker2']
agents = ['wazuh-agent1', 'wazuh-agent2']
workers = ['wazuh-worker1', 'wazuh-worker2']
groups_created = []
first_time_check = "synced"
second_time_check = "synced"
network = {}
client_keys = {}

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_group_sync_cases.yml'))
wdb_query = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'script/wdb-query.py')

@pytest.fixture
def delete_logs():
    clean_cluster_logs(testinfra_hosts, host_manager)

def delete_all_groups():
    global groups_created
    groups_created = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups')
    for group in groups:
        if group in groups_created:
            response = host_manager.make_api_call(host=testinfra_hosts[0], token=host_manager.get_api_token(testinfra_hosts[0]), method='DELETE',
                                                      endpoint=f'/groups?groups_list={group}')
            assert response['status'] == 200, f"Failed to delete {group} group: {response}"

@pytest.fixture
def group_creation():
    delete_all_groups()
    for group in groups:
        response = host_manager.make_api_call(host=testinfra_hosts[0], token=host_manager.get_api_token(testinfra_hosts[0]), method='POST',
                                                      endpoint='/groups', request_body={'group_id': group})
        assert response['status'] == 200, f"Failed to create {group} group: {response}"
    
@pytest.fixture
def agent_group_assignation():
    agent_ids = host_manager.run_command(testinfra_hosts[0], f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys').split()
    for group in groups:
        for agent_id in agent_ids:
            response = host_manager.make_api_call(host=testinfra_hosts[0], token=host_manager.get_api_token(testinfra_hosts[0]), method='PUT',
                                                      endpoint=f'/agents/{agent_id}/group/{group}')
            assert response['status'] == 200, f"Failed to assign agent {agent_id} in {group} group: {response}"
    
@pytest.fixture
def delete_group_folder(test_case):
    groups_created = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups')
    if test_case['test_case']['group_deleted'] in groups_created:
        host_manager.run_command(test_case['test_case']['host'], f"rm -r {WAZUH_PATH}/etc/shared/{test_case['test_case']['group_deleted']} -f")
    
@pytest.fixture
def wdb_query_creator():
    wdb = read_file(wdb_query)
    host_manager.modify_file_content(host=testinfra_hosts[0], path=f'{WAZUH_PATH}/wdb-query.py',content=wdb)

def query_database(): 
    query = 'global sql select group_sync_status from agent;'
    response= host_manager.run_command(testinfra_hosts[0], f'python3 {WAZUH_PATH}/wdb-query.py "{query}"')
    return response 

@pytest.fixture
def kill_initial_syncreq():
    result = query_database()
    while 'syncreq' in result:
        time.sleep(1)
        result = query_database()

@pytest.fixture
def first_check():
    global first_time_check
    first_time_check = "synced"
    s_time = 15
    for i in range(s_time):
        time.sleep(0.25)
        result = query_database()
        if 'syncreq' in result:
            first_time_check = "syncreq"

@pytest.fixture          
def second_check():
    time.sleep(10)
    global second_time_check
    second_time_check = "synced"
    result = query_database()
    if 'syncreq' in result:
        second_time_check = "syncreq"    
        
@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])

def test_group_sync_status(test_case, delete_logs, 
                           group_creation, agent_group_assignation, 
                           wdb_query_creator, kill_initial_syncreq, delete_group_folder,
                           first_check, second_check):

    '''
    description: Delete a group folder in wazuh server cluster and check group_sync status in 2 times.
    wazuh_min_version: 4.4.0
    parameters:
        - test_case:
            type: list
            brief: List of tests to be performed.
        - delete_logs
            type: function
            brief: Delete logs generally talking           
        - group_creation:
            type: function
            brief: Delete and create from zero all the groups that are going to be used for testing
        - agent_group_assignation:
            type: function
            brief: Assign agents to groups
        - wdb_query_creator
            type: function
            brief: Creates a python scripts to do specific queries as a cluster         
        - kill_initial_syncreq:
            type: function
            brief: Wait until syncreqs related with the test-environment setting get neutralized
        - delete_group_folder:
            type: function
            brief: Delete the folder-group assigned by test case (trigger)
        - check_first_time:
            type: function
            brief: Check for group_sync status after the trigger    
        - check_second_time:
            type: function
            brief: Check for group_sync changes after 10 seconds
                       
    assertions:
        - Verify that group_sync status changes according the trigger.
        
    input_description: Different use cases are found in the test module and include parameters.
                       
    expected_output:
        - If the group-folder is deleted from master cluster, it is expected to find a syncreq group_sync status until it gets synced.
        - If the group-folder is deletef rom a worker cluster, it is expected that master cluster recreates groups without syncreq status.
    '''
    #Results
    assert test_case['test_case']['first_time_check'] == first_time_check 
    assert test_case['test_case']['second_time_check'] == second_time_check  






