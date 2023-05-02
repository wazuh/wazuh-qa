'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Wazuh manager should be able to create merged.mg file in order to share files with group of agents.
       In order to do it, when new files are present in any directory in /var/ossec/share/, 
       those files must be monitored and to be taken in consideration by merged.mg
tier: 1, 2
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
    - https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html
'''

import os
import pytest
import time
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.system import HostManager
from system import assign_agent_to_new_group, clean_cluster_logs, create_new_agent_group, delete_group_of_agents,restart_cluster

folder_value = False
merged_malformed_check_value = False
log_value = False
reset_files = {
    'default': ['TestFile', 'TestFile2', 'EmptyFile', 'EmptyFile2', 'EmptyFile3', 'EmptyFile4', 'EmptyFile5', 'EmptyFile6', 
                'EmptyFile7', 'EmptyFile8', 'EmptyFile9', 'EmptyFile10'],
    'TestGroup1': ['TestFileInTestGroup', 'TestFileInTestGroup2', 'EmptyFileInGroup', 'EmptyFileInGroup2', 
                   'EmptyFileInGroup3', 'EmptyFileInGroup4', 'EmptyFileInGroup5', 'EmptyFileInGroup6', 'EmptyFileInGroup7', 
                   'EmptyFileInGroup8', 'EmptyFileInGroup9', 'EmptyFileInGroup10']
}
testinfra_hosts = ['wazuh-manager', 'wazuh-agent1']

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              '..', 'provisioning', 'one_manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 
                               '..', 'provisioning', 'one_manager_agent', 'roles', 'agent-role', 'files', 'ossec.conf')
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_correct_merged_file_generation_cases.yml'))

#pytestmark = [pytest.mark.cluster, pytest.mark.one_manager_agent_env]

def check_merged(group):
    time.sleep(1)
    check = False
    value = host_manager.run_command(testinfra_hosts[0], f'ls {WAZUH_PATH}/etc/shared/{group} -la | grep merged')
    if 'merged.mg' in value:
        check = True
    assert check

def read_merged(group):
    return host_manager.run_command(
        testinfra_hosts[0], f'cat {WAZUH_PATH}/etc/shared/{group}/merged.mg'
    )

def add_zero_file(group, name):
    host_manager.run_command(testinfra_hosts[0], f'touch {WAZUH_PATH}/etc/shared/{group}/{name}.txt')

def add_non_zero_file(name, content, group='default'):
    host_manager.run_command(testinfra_hosts[0], f'touch {WAZUH_PATH}/etc/shared/{group}/{name}.txt')
    host_manager.modify_file_content(host=testinfra_hosts[0], path=f'{WAZUH_PATH}/etc/shared/{group}/{name}.txt',
                                            content=content) 

@pytest.fixture
def clear_files_and_directories():
    for file in reset_files['default']:
        host_manager.run_command(testinfra_hosts[0], f'rm {WAZUH_PATH}/etc/shared/default/{file}.txt -f')
    for file in reset_files['TestGroup1']:
        host_manager.run_command(testinfra_hosts[0], f'rm {WAZUH_PATH}/etc/shared/TestGroup1/{file}.txt -f')
    delete_group_of_agents(testinfra_hosts[0], 'TestGroup1', host_manager)
    host_manager.run_command(testinfra_hosts[0], f'rm -r {WAZUH_PATH}/etc/shared/TestGroup1 -f')   
    create_new_agent_group(testinfra_hosts[0], 'TestGroup1', host_manager)
    assign_agent_to_new_group(testinfra_hosts[0], 'TestGroup1', host_manager.run_command('wazuh-manager', 
                                                                                        f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys'), host_manager)

@pytest.fixture
def clean_cluster():
    clean_cluster_logs(testinfra_hosts, host_manager)

@pytest.fixture
def stop_manager(test_case):
    time.sleep(1)
    if test_case['test_case'][0]['test_type'] == 'start':
        host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/wazuh-control stop')

@pytest.fixture
def trigger(test_case):
    if test_case['test_case'][0]['trigger_value'] == "remove":
        host_manager.run_command(testinfra_hosts[0], f'rm {WAZUH_PATH}/etc/shared/default/merged.mg -f')
    if test_case['test_case'][0]['trigger_value'] == "add_files":
        if test_case['test_case'][0]['content']  == 'zero':
            if test_case['test_case'][0]['number'] == '1':
                add_zero_file(test_case['test_case'][0]['folder'], test_case['test_case'][0]['name'])
            if test_case['test_case'][0]['number'] == 'several':
                for file in test_case['test_case'][0]['name']:
                    add_zero_file(test_case['test_case'][0]['folder'], file)
        if test_case['test_case'][0]['content']  != 'zero':
            if test_case['test_case'][0]['number'] == '1':
                add_non_zero_file(test_case['test_case'][0]['name'], test_case['test_case'][0]['content'], test_case['test_case'][0]['folder'])
            if test_case['test_case'][0]['number'] == 'several':
                for file in test_case['test_case'][0]['name']:
                    add_non_zero_file(file, test_case['test_case'][0]['content'], test_case['test_case'][0]['folder'])

@pytest.fixture
def check_closed_merged(test_case, group='default'):
    check = False
    value = host_manager.run_command(testinfra_hosts[0], f'ls {WAZUH_PATH}/etc/shared/{group} -la | grep merged')
    if 'merged.mg' in value:
        check = True
    if test_case['test_case'][0]['trigger_value'] == 'remove' and test_case['test_case'][0]['test_type'] == 'start':
        assert not check

@pytest.fixture
def restart_or_sleep(test_case):
    group = 'default'
    if test_case['test_case'][0]['test_type'] == 'start':
        restart_cluster(testinfra_hosts, host_manager)
    if test_case['test_case'][0]['test_type'] == '10s': 
        time.sleep(10)
    if test_case['test_case'][0]['folder'] == 'TestGroup1':
        group = 'TestGroup1'
    check_merged(group)

@pytest.fixture
def check_folder(test_case):
    global folder_value
    value_files = False
    value_merged = False
    counter = 0
    if test_case['test_case'][0]['folder'] is None: folder = 'default'
    else:
        folder = test_case['test_case'][0]['folder']
    files_info = host_manager.run_command(testinfra_hosts[0], f'ls {WAZUH_PATH}/etc/shared/{folder}')
    if test_case['test_case'][0]['name'] is not None:
        for file in test_case['test_case'][0]['name']:
            if file in files_info:
                counter = counter + 1
        if counter == len(test_case['test_case'][0]['name']):
            value_files = True
    if test_case['test_case'][0]['name'] is None:
        value_files = True
    if 'merged.mg' in files_info:
        value_merged = True
    if value_files and value_merged:
        folder_value = True

@pytest.fixture
def check_merged_malformed(test_case, group='default'):
    global merged_malformed_check_value
    if test_case['test_case'][0]['malformed_value'] is not None:
        folder_info = read_merged(test_case['test_case'][0]['folder'])
        for value in test_case['test_case'][0]['malformed_value']:
            if value in folder_info:
                merged_malformed_check_value = True
    else : merged_malformed_check_value = True

@pytest.fixture
def check_log(test_case):
    global log_value
    counter = 0
    if test_case['test_case'][0]['log_content'] is not None:
        if test_case['test_case'][0]['content'] == "zero":
            logs_info = host_manager.run_command(testinfra_hosts[0], f'cat {WAZUH_PATH}/logs/ossec.log')  
            for expected_log in test_case['test_case'][0]['log_content']:
                if expected_log in logs_info:
                    counter= counter + 1
        if len(test_case['test_case'][0]['log_content']) == counter:
            log_value = True
    else: log_value = True

@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])

def test_correct_merged_file_generation(test_case, clear_files_and_directories, clean_cluster, 
                                        stop_manager, trigger, check_closed_merged, restart_or_sleep,
                                        check_folder, check_merged_malformed, check_log):
    
    '''
        description: Checking correct merged file generation.
        wazuh_min_version: 4.5.0
        parameters:
            - test_case:
                type: list
                brief: List of tests to be performed.
            - clear_files_and_directories:
                type: function
                brief: Clear files and directories, reset initial conditions in /var/ossec/share (includes agent enrollment).
            - clean_cluster:
                type: function
                brief: Clear wazuh-manager logs.
            - stop_manager:
                type: function
                brief: Stop the wazuh-manager.            
            - trigger:
                type: function
                brief: Depending on the test, there are basically 2 triggers: remove merged.mg and add_files.
            - check_closed_merged:
                type: function
                brief: Only in 'start' type of test, check if the merged is closed.             
            - restart_or_sleep:
                type: function
                brief: Restart or sleep for 10 seconds the manager.     
            - check_folder:
                type: function
                brief: Checks merged and added file.    
            - check_merged_malformed:
                type: function
                brief: Check merged information controlling the information about added file.    
            - check_log:
                type: function
                brief: Check logs if there are information about empty files (added).
                
        assertions:
            - check merged.mg in the selected folder and the created file.
            - check if merged contains the correct information.
            - check if log contains the proper information in case the added file has no data.
            
        input_description: Different use cases are found in the test module and include parameters.
                        
        expected_output:
            - merged.mg should be created and modified automatically considering the file/s and its/their information.
    '''
    
    assert folder_value
    assert merged_malformed_check_value 
    assert log_value
