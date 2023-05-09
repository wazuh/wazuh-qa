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
from wazuh_testing import T_1, T_10
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.system import HostManager
from system import assign_agent_to_new_group, clean_cluster_logs, create_new_agent_group, delete_agent_group, restart_cluster

#pytestmark = [pytest.mark.cluster, pytest.mark.one_manager_agent_env]

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

@pytest.fixture
def cleaning_environment(test_case):
    
    for file in reset_files['default']:
        host_manager.run_command(testinfra_hosts[0], f'rm {WAZUH_PATH}/etc/shared/default/{file}.txt -f')
        
    for file in reset_files['TestGroup1']:
        host_manager.run_command(testinfra_hosts[0], f'rm {WAZUH_PATH}/etc/shared/TestGroup1/{file}.txt -f')
        
    delete_agent_group(testinfra_hosts[0], 'TestGroup1', host_manager, 'api')
    host_manager.run_command(testinfra_hosts[0], f'rm -r {WAZUH_PATH}/etc/shared/TestGroup1 -f')   
    create_new_agent_group(testinfra_hosts[0], 'TestGroup1', host_manager)
    
    assign_agent_to_new_group(testinfra_hosts[0], 'TestGroup1', host_manager.run_command('wazuh-manager', 
                                                                                        f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys'), host_manager)
    clean_cluster_logs(testinfra_hosts, host_manager)
    
    time.sleep(T_1)
    
    if test_case['test_case'][0]['test_type'] == 'start':
        host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/wazuh-control stop')

@pytest.fixture
def trigger_and_check_merged(test_case):
    
    if test_case['test_case'][0]['trigger_value'] == "remove":
        host_manager.run_command(testinfra_hosts[0], f'rm {WAZUH_PATH}/etc/shared/default/merged.mg -f')
        
    if test_case['test_case'][0]['trigger_value'] == "add_files":
        
        if test_case['test_case'][0]['content']  == 'zero':
            if test_case['test_case'][0]['number'] == '1':
                host_manager.run_command(testinfra_hosts[0], 
                                         f"touch {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/{test_case['test_case'][0]['name']}.txt")
            
            if test_case['test_case'][0]['number'] == 'several':
                for file in test_case['test_case'][0]['name']:
                    host_manager.run_command(testinfra_hosts[0], 
                                             f"touch {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/{file}.txt")      
        if test_case['test_case'][0]['content']  != 'zero':
            
            if test_case['test_case'][0]['number'] == '1':
                host_manager.run_command(testinfra_hosts[0], 
                                         f"touch {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/{test_case['test_case'][0]['name']}.txt")
                host_manager.modify_file_content(host=testinfra_hosts[0], path=f"{WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/{test_case['test_case'][0]['name']}.txt",
                                                            content=test_case['test_case'][0]['content']) 
        
            if test_case['test_case'][0]['number'] == 'several':
                for file in test_case['test_case'][0]['name']:
                    host_manager.run_command(testinfra_hosts[0], 
                                             f"touch {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/{test_case['test_case'][0]['name']}.txt")
                    host_manager.modify_file_content(host=testinfra_hosts[0], 
                                                     path=f"{WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/{test_case['test_case'][0]['name']}.txt",
                                                                                        content=test_case['test_case'][0]['content']) 
            
    if test_case['test_case'][0]['test_type'] == 'start' and test_case['test_case'][0]['trigger_value'] == 'remove':
        assert 'merged.mg' not in host_manager.run_command(testinfra_hosts[0], f'ls {WAZUH_PATH}/etc/shared/default -la | grep merged')

@pytest.fixture
def restart_or_sleep(test_case):
    if test_case['test_case'][0]['test_type'] == 'start':
        restart_cluster(testinfra_hosts, host_manager)
        time.sleep(T_1)
        
    if test_case['test_case'][0]['test_type'] == '10s': 
        time.sleep(T_10)
        
    assert 'merged.mg' in host_manager.run_command(testinfra_hosts[0], f"ls {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder'] } -la | grep merged")

@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])

def test_correct_merged_file_generation(test_case, cleaning_environment, trigger_and_check_merged, restart_or_sleep):
    
    '''
        description: Checking correct merged file generation.
        wazuh_min_version: 4.5.0
        parameters:
            - test_case:
                type: list
                brief: List of tests to be performed.
            - cleaning_environment:
                type: function
                brief: Clear files, directories and logs, reset initial conditions in /var/ossec/share (includes agent enrollment).
                        Also stops the manager if it is required.          
            - trigger_and_check_merged:
                type: function
                brief: Depending on the test, there are basically 2 triggers: remove merged.mg and add_files. Also checks merged if the case is required.         
            - restart_or_sleep:
                type: function
                brief: Restart or sleep for 10 seconds the manager and check merged.     
        assertions:
            - check merged.mg in the selected folder and the created file.
            - check if merged contains the correct information.
            - check if log contains the proper information in case the added file has no data.
        input_description: Different use cases are found in the test module and include parameters.
        expected_output:
            - merged.mg should be created and modified automatically considering the file/s and its/their information.
    '''
    
    if test_case['test_case'][0]['name'] is not None:
        counter_files = 0
        for file in test_case['test_case'][0]['name']:
            if file in host_manager.run_command(testinfra_hosts[0], f"ls {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}"):
                counter_files = counter_files + 1
        assert counter_files == len(test_case['test_case'][0]['name'])
        
    assert 'merged.mg' in host_manager.run_command(testinfra_hosts[0], f"ls {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}")
    
    if test_case['test_case'][0]['malformed_value'] is not None:
        for value in test_case['test_case'][0]['malformed_value']:
            assert value in host_manager.run_command(testinfra_hosts[0], f"cat {WAZUH_PATH}/etc/shared/{test_case['test_case'][0]['folder']}/merged.mg")
    
    if test_case['test_case'][0]['content'] == "zero":
        counter_logs = 0
        for expected_log in test_case['test_case'][0]['log_content']:
            
            if expected_log in host_manager.run_command(testinfra_hosts[0], f'cat {WAZUH_PATH}/logs/ossec.log')  :
                counter_logs = counter_logs + 1
        assert len(test_case['test_case'][0]['log_content']) == counter_logs


