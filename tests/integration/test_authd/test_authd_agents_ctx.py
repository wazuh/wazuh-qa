# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os, shutil

import pytest
import socket
import ssl
import subprocess
import time
import yaml
from datetime import datetime

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

def load_tests(path):
    """ Loads a yaml file from a path 
    Return 
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-db', None, True), ('ossec-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
# Tests

@pytest.fixture(scope="function")
def set_up_groups(request):
    subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', 'TestGroup', '-q'])
    yield
    subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', 'TestGroup', '-q'])

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param
    
@pytest.fixture(scope="module")
def clean_agents_ctx():    
    # Stop Wazuh
    control_service('stop')

    clean_keys()
    clean_groups()
    clean_agentinfo()
    clean_agentstimestamp()

    # Start Wazuh
    control_service('start')

def clean_keys():
    client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
    truncate_file(client_keys_path)

def clean_groups():
    groups_folder = os.path.join(WAZUH_PATH, 'queue', 'agent-groups')
    for filename in os.listdir(groups_folder):
        file_path = os.path.join(groups_folder, filename)
        try:
            os.unlink(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def clean_agentinfo():
    agentinfo_folder = os.path.join(WAZUH_PATH, 'queue', 'agent-info')
    for filename in os.listdir(agentinfo_folder):
        file_path = os.path.join(agentinfo_folder, filename)
        try:
            os.unlink(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))
        
def clean_agentstimestamp():
    timestamp_path = os.path.join(WAZUH_PATH, 'queue', 'agents-timestamp')
    truncate_file(timestamp_path)

def check_agent_groups(id, expected, timeout=10):
    group_path = os.path.join(WAZUH_PATH, 'queue', 'agent-groups', id)
    wait = time.time() + timeout
    while time.time() < wait: 
        ret = os.path.exists(group_path)
        if ret == expected:
            return True
    return False

def check_client_keys(id, expected):
    client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
    found = False
    try:
        with open(client_keys_path) as client_file:
            client_lines = client_file.read().splitlines() 
            for line in client_lines:
                data = line.split(" ")
                if data[0] == id:
                    found = True
                    break
    except IOError:
        raise

    if found == expected:
        return True
    else:
        return False


def check_agent_timestamp(id, name, ip, expected):
    timestamp_path = os.path.join(WAZUH_PATH, 'queue', 'agents-timestamp')    
    line = "{} {} {}".format(id,name,ip)
    found = False
    try:
        with open(timestamp_path) as file:
            file_lines = file.read().splitlines() 
            for file_line in file_lines:                
                if line in file_line:
                    found = True
                    break
    except IOError:
        raise

    if found == expected:
        return True
    else:
        return False

def check_agent_info(name, ip, expected):
    agent_info_file = name+'-'+ip
    agent_info_path = os.path.join(WAZUH_PATH, 'queue', 'agent-info', agent_info_file)
    if expected == os.path.exists(agent_info_path):
        return True
    else:
        return False

def create_agent_info(name, ip):
    agent_info_file = name+'-'+ip
    agent_info_path = os.path.join(WAZUH_PATH, 'queue', 'agent-info', agent_info_file)
    try:
        file = open(agent_info_path, 'w')
        file.close()
    except IOError:
        raise

def register_agent(message):
    receiver_sockets[0].open()
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout: 
            raise ConnectionResetError('Manager did not respond to sent message!')
    time.sleep(0.5)
    return response

def test_ossec_authd_agents_ctx_main( clean_agents_ctx, get_configuration, set_up_groups, configure_environment, configure_mitm_environment, connect_to_sockets_module, wait_for_agentd_startup):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """ 
    SUCCESS_RESPONSE = "OSSEC K:'"

    #Register first agents
    response = register_agent("OSSEC A:'userA' G:'TestGroup' IP:'192.0.0.0'") 
    create_agent_info('userA','192.0.0.0') #Simulate agent_info was created

    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received' 
    assert check_client_keys('001', True), 'Agent key was never created' 
    assert check_agent_groups('001', True), 'Agent group was never created'
    assert check_agent_info('userA', '192.0.0.0', True), 'Agent_info was never created'
    assert check_agent_timestamp('001', 'userA', '192.0.0.0', True), 'Agent_timestamp was never created'

    response = register_agent("OSSEC A:'userB' G:'TestGroup'")    
    create_agent_info('userB','any') #Simulate agent_info was created
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received' 
    assert check_client_keys('002', True), 'Agent key was never created'
    assert check_agent_groups('002', True), 'Agent group was never created'
    assert check_agent_info('userB', 'any', True), 'Agent_info was never created'
    assert check_agent_timestamp('002', 'userB', 'any', True), 'Agent_timestamp was never created'

    #Register agent with duplicate IP
    response = register_agent("OSSEC A:'userC' G:'TestGroup' IP:'192.0.0.0'")
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('003', True), 'Agent key was never created'
    assert check_client_keys('001', False), 'Agent key was not removed'    
    assert check_agent_groups('003', True), 'Agent group was never created'
    assert check_agent_groups('001', False), 'Agent group was not removed'
    assert check_agent_timestamp('003', 'userC', '192.0.0.0', True), 'Agent_timestamp was never created'
    assert check_agent_timestamp('001', 'userA', '192.0.0.0', False), 'Agent_timestamp was not removed'
    assert check_agent_info('userA', '192.0.0.0', False), 'Agent_info was not removed'
    
    #Register agent with duplicate Name
    response = register_agent("OSSEC A:'userB' G:'TestGroup'")
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('004', True), 'Agent key was never created'
    assert check_client_keys('002', False), 'Agent key was not removed'   
    assert check_agent_groups('004', True), 'Agent group was never created'
    assert check_agent_groups('002', False), 'Agent group was not removed'
    assert check_agent_timestamp('004', 'userB', 'any', True), 'Agent_timestamp was never created'
    assert check_agent_timestamp('002', 'userB', 'any', False), 'Agent_timestamp was not removed'
    assert check_agent_info('userB', 'any', False), 'Agent_info was not removed'
