# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
import socket
import ssl

from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

def load_tests(path):
    """ Loads a yaml file from a path 
    Retrun 
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'manager_conf.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
ip_name_configuration_tests = load_tests(os.path.join(test_data_path, 'ip_name_tests.yaml'))

DEFAULT_FORCE_INSERT = "yes"
DEFAULT_USE_USER_IP = 'no'
DEFAULT_USE_PASSWORD = 'no'
CLIENT_KEY_ENTRY_LEN = 4

conf_params = {'USE_SOURCE_IP' : [], 'FORCE_INSERT' : [], 'USE_PASSWORD' : []}

for case in ip_name_configuration_tests:
    conf_params['USE_SOURCE_IP'].append(case.get('USE_SOURCE_IP', DEFAULT_USE_USER_IP))
    conf_params['FORCE_INSERT'].append(case.get('FORCE_INSERT', DEFAULT_FORCE_INSERT))
    conf_params['USE_PASSWORD'].append(case.get('USE_PASSWORD', DEFAULT_USE_PASSWORD))

p, m = generate_params(extra_params=conf_params, modes=['scheduled']*len(ip_name_configuration_tests))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-db', None, True), ('ossec-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
# fixtures

test_index = 0

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    test_index = getattr(request.module, 'test_index')
    yield request.param
    setattr(request.module, 'test_index', test_index + 1) 

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop')
     # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)
    # Start Wazuh
    control_service('start')

    """Wait until agentd has begun"""
    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)

def clean_client_keys_file():
    # Stop Wazuh
    control_service('stop')

    # Clean client.keys
    try:
        with open(client_keys_path, 'w') as client_file:
            client_file.close()        
    except IOError as exception:
        raise

    # Start Wazuh
    control_service('start')

    """Wait until agentd has begun"""
    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)

def check_client_keys_file(response):
    try:
        with open(client_keys_path) as client_file:
            client_lines = client_file.readlines()
            for line in client_lines:
                if line in response:
                    client_file.close()
                    return line
    except IOError as exception:
        raise
    return ""


    
#@pytest.mark.parametrize('test_case', [case['test_case'] for case in ssl_configuration_tests])
def test_ossec_auth_configurations(get_configuration, configure_environment, configure_mitm_environment):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_cases, dict with following keys:
            - expect: What we are expecting to happen
                1. open_error: Should fail when trying to do ssl handshake
                2. output: Expects an output message from the manager
            - input: message that will be tried to send to the manager
            - output: expected response (if any)
    """   
    test_case = ip_name_configuration_tests[test_index]['test_case']
    override_wazuh_conf(get_configuration)
    for config in test_case:
        address, family, connection_protocol = receiver_sockets_params[0]
        
        expect = config['expect']
        insert_prev = config['insert_prev_agent_same_name']
        if config['clean_client_keys'] and config['clean_client_keys'] == 'yes':
            clean_client_keys_file()
        

        #insert prev agent to force repeated case
        if insert_prev == "yes":
            SSL_socket_prev = SocketController(address, family=family, connection_protocol=connection_protocol)
            try:
                SSL_socket_prev.open()
            except ssl.SSLError as exception:
                if expect == 'open_error':
                    # We expected the error here, check message
                    assert config['error'] in str(exception), 'Expected message does not match!'
                    continue
                else:
                    # We did not expect this error, fail test
                    raise
            SSL_socket_prev.send(config['input'], size=False)
            if expect == 'output':
                # Prev output is expected
                expected = "OSSEC K:'"
                if expected:
                    response = SSL_socket_prev.receive().decode()
                    assert response, 'Failed connection in prev insert'
                    #assert response == prev
                    assert response[:len(expected)] == expected, 'Failed test case in prev insert'
                    if expected == "OSSEC K:'":
                        assert check_client_keys_file(response) in response[:len(expected)]
            SSL_socket_prev.close()


        SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol)
        try:
            SSL_socket.open()
        except ssl.SSLError as exception:
            if expect == 'open_error':
                # We expected the error here, check message
                assert config['error'] in str(exception), 'Expected message does not match!'
                continue
            else:
                # We did not expect this error, fail test
                raise
        
        SSL_socket.send(config['input'], size=False)
        if expect == 'output':
            # Output is expected
            expected = config['output']
            if expected:
                response = SSL_socket.receive().decode()
                assert response, 'Failed connection stage {}: {}'.format(test_case.index(config) + 1, config['stage'])
                #assert response == prev
                assert response[:len(expected)] == expected, 'Failed test case {}: {}'.format(config['input'], config['output'])
                if expected == "OSSEC K:'":
                    assert check_client_keys_file(response) in response[:len(expected)]
    return