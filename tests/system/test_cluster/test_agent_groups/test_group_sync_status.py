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
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.file import read_file, read_yaml
from wazuh_testing.tools.system import HostManager
from system import assign_agent_to_new_group, create_new_agent_group, delete_group_of_agents, execute_wdb_query

pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

testinfra_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2', 'wazuh-agent1', 'wazuh-agent2']
groups = ['group_master', 'group_worker1', 'group_worker2']
agents = ['wazuh-agent1', 'wazuh-agent2']
workers = ['wazuh-worker1', 'wazuh-worker2']
groups_created = []
first_time_check = "synced"
second_time_check = "synced"
network = {}

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_group_sync_cases.yml'))
wdb_query = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'script/wdb-query.py')
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               '..', '..' ,'provisioning', 'enrollment_cluster', 'roles', 'agent-role', 'files', 'ossec.conf')

def get_ip_directions():
    global network
    for host in testinfra_hosts:
        network[host] = host_manager.get_host_ip(host, 'eth0')
        
def delete_all_groups():
    for group in groups:
        delete_group_of_agents(testinfra_hosts[0],group,host_manager)

def query_database(): 
    query = "global 'sql select group_sync_status from agent;'"
    response = execute_wdb_query(query, testinfra_hosts[0], host_manager)
    return response 

def first_check():
    global first_time_check
    first_time_check = "synced"
    s_time = 15
    for i in range(s_time):
        time.sleep(0.25)
        result = query_database()
        if 'syncreq' in result:
            first_time_check = "syncreq"
    
def second_check():
    time.sleep(10)
    global second_time_check
    second_time_check = "synced"
    result = query_database()
    if 'syncreq' in result:
        second_time_check = "syncreq"   
        
@pytest.fixture
def network_configuration():
    get_ip_directions()
    for worker in workers:
        old_agent_configuration = read_file(agent_conf_file)
        new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                            f"<address>{network[worker][0]}</address>")
    
        host_manager.modify_file_content(host=agents[worker.index(worker)], path=f'{WAZUH_PATH}/etc/ossec.conf',
                                        content=new_configuration)
        host_manager.get_host(testinfra_hosts[0]).ansible('command', f'service wazuh-manager restart', check=False)
    for agent in agents:
        host_manager.get_host(agent).ansible('command', f'service wazuh-agent restart', check=False)
               
@pytest.fixture
def group_creation():
    delete_all_groups()
    for group in groups:
        create_new_agent_group(testinfra_hosts[0], group, host_manager)

@pytest.fixture
def agent_group_assignation():
    agent_ids = host_manager.run_command(testinfra_hosts[0], f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys').split()
    for group in groups:
        for agent_id in agent_ids:
            assign_agent_to_new_group(testinfra_hosts[0], group, agent_id, host_manager)
    
@pytest.fixture
def delete_group_folder(test_case):
    groups_created = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_groups')
    if test_case['test_case']['group_deleted'] in groups_created:
        host_manager.run_command(test_case['test_case']['host'], f"rm -r {WAZUH_PATH}/etc/shared/{test_case['test_case']['group_deleted']} -f")

@pytest.fixture
def wait_end_initial_syncreq():
    result = query_database()
    while 'syncreq' in result:
        time.sleep(1)
        result = query_database()
                    
@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])

def test_group_sync_status(test_case, network_configuration, 
                           group_creation, agent_group_assignation, 
                           wait_end_initial_syncreq, delete_group_folder):

    '''
    description: Delete a group folder in wazuh server cluster and check group_sync status in 2 times.
    wazuh_min_version: 4.4.0
    parameters:
        - test_case:
            type: list
            brief: List of tests to be performed.
        - network_configuration
            type: function
            brief: Delete logs generally talking           
        - group_creation:
            type: function
            brief: Delete and create from zero all the groups that are going to be used for testing
        - agent_group_assignation:
            type: function
            brief: Assign agents to groups      
        - wait_end_initial_syncreq:
            type: function
            brief: Wait until syncreqs related with the test-environment setting get neutralized
        - delete_group_folder:
            type: function
            brief: Delete the folder-group assigned by test case (trigger)
                       
    assertions:
        - Verify that group_sync status changes according the trigger.
        
    input_description: Different use cases are found in the test module and include parameters.
                       
    expected_output:
        - If the group-folder is deleted from master cluster, it is expected to find a syncreq group_sync status until it gets synced.
        - If the group-folder is deletef rom a worker cluster, it is expected that master cluster recreates groups without syncreq status.
    '''
    #Checks
    first_check()
    second_check()
             
    #Results
    assert test_case['test_case']['first_time_check'] == first_time_check 
    assert test_case['test_case']['second_time_check'] == second_time_check  






