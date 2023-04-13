'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
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
from time import sleep

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.file import read_file, read_yaml, write_file
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.utils import format_ipv6_long
import time
import subprocess
import threading
import pytest

#Parameters
testinfra_hosts = ['wazuh-master', 'wazuh-worker1','wazuh-worker2']
groups = ['g_master', 'g_worker1', 'g_worker2']
agents = ['wazuh-agent1', 'wazuh-agent2']
workers = ['wazuh-worker1', 'wazuh-worker2']
groups_created = []
syncreq = "synced"
end_syncreq = "synced"
network = {}
client_keys = {}

#Endpoints
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_group_sync_cases.yml'))
wdb_query = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'wdb-query.py')

@pytest.fixture(scope='function')
def delete_logs():
    for infra in testinfra_hosts:
        host_manager.clear_file(host=infra, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    for agent in agents:
        host_manager.clear_file(host=agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
        
def get_api_token():
    global host_manager
    return host_manager.get_api_token(testinfra_hosts[0])

@pytest.fixture(scope='function')
def group_creation():
    #Delete first
    delete_AllGroups()
    for group in groups:
        response = host_manager.make_api_call(host=testinfra_hosts[0], token=get_api_token(), method='POST',
                                                      endpoint='/groups', request_body={'group_id': group})
        assert response['status'] == 200, f"Failed to create {group} group: {response}"
        #print("Group Created: "+ group)
    #print(host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups'))

def delete_AllGroups():
    global groups_created
    groups_created = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups')
    for group in groups:
        if group in groups_created:
            response = host_manager.make_api_call(host=testinfra_hosts[0], token=get_api_token(), method='DELETE',
                                                      endpoint=f'/groups?groups_list={group}')
            assert response['status'] == 200, f"Failed to delete {group} group: {response}"
            #print("Group Deleted: " + group)

@pytest.fixture(scope='function')
def agent_groupAssignation():
    agent_ids = host_manager.run_command(testinfra_hosts[0], f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys').split()
    for group in groups:
        for agent_id in agent_ids:
            response = host_manager.make_api_call(host=testinfra_hosts[0], token=get_api_token(), method='PUT',
                                                      endpoint=f'/agents/{agent_id}/group/{group}')
            assert response['status'] == 200, f"Failed to assign agent {agent_id} in {group} group: {response}"
            #print('Agent assigned: ' + agent_id + ' into group: '+ group)
    #print(host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups'))

@pytest.fixture(scope='function')
def delete_group_folder(test_case):
    groups_created = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups')
    if test_case['test_case']['g_deleted'] in groups_created:
        host_manager.run_command(test_case['test_case']['host'], f"rm -r {WAZUH_PATH}/etc/shared/{test_case['test_case']['g_deleted']} -f")
        #print("Group deleted: "+ test_case['test_case']['g_deleted'] + " from node:" + test_case['test_case']['host'])
    else: 
        #print("The group does not exist")
        pass

@pytest.fixture(scope='function')
def wdb_query_creator():
    wdb = read_file(wdb_query)
    host_manager.modify_file_content(host=testinfra_hosts[0], path=f'{WAZUH_PATH}/wdb-query.py',content=wdb)

def query_database(): 
    query = 'global sql select group_sync_status from agent;'
    response= host_manager.run_command(testinfra_hosts[0], f'python3 {WAZUH_PATH}/wdb-query.py "{query}"')
    #print(response)
    return response 

@pytest.fixture(scope='function')
def check_initial_syncreq():
    result = query_database()
    while 'syncreq' in result:
        time.sleep(1)
        #print("Waiting for syncreq neutralization")
        result = query_database()

@pytest.fixture(scope='function')
def check_afterDel_syncreq():
    global syncreq
    syncreq = "synced"
    s_time = 15
    for i in range(s_time):
        time.sleep(0.25)
        result = query_database()
        #print('Scan: ' + str((i/s_time)*100)[0:4] + '%')
        if 'syncreq' in result:
            syncreq = "syncreq"
            #print("After delete syncreq detected")

@pytest.fixture(scope='function')            
def check_syncreq_end():
    time.sleep(10)
    global end_syncreq
    end_syncreq = "synced"
    result = query_database()
    if 'syncreq' in result:
        end_syncreq = "syncreq"    
        #print("Second time syncreq detected")

@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])

def test_group_sync_status(test_case,  
                           group_creation, agent_groupAssignation, wdb_query_creator, check_initial_syncreq,
                           delete_group_folder, check_afterDel_syncreq, check_syncreq_end):
    '''
    description: Delete a group folder in wazuh server cluster and check group_sync status in 2 times.
    wazuh_min_version: 4.4.0
    parameters:
        - test_case:
            type: list
            brief: List of tests to be performed.
        - group_creation:
            type: function
            brief: Delete and create from zero all the groups that are going to be used for testing
        - agent_groupAssignation:
            type: function
            brief: Assign agents to groups
        - wdb_query_creator:
            type: function
            brief: Create the script to query group-sync status
        - check_initial_syncreq:
            type: function
            brief: Wait until syncreqs related with the test-environment setting get neutralized
        - delete_group_folder:
            type: function
            brief: Delete the folder-group assigned by test case (trigger)
        - check_afterDel_syncreq:
            type: function
            brief: Check for group_sync status after the trigger    
         - check_syncreq_end:
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
    assert test_case['test_case']['first_time'] == syncreq 
    assert test_case['test_case']['second_time'] == end_syncreq  