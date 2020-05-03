# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
import socket
import ssl
import time
import subprocess

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
authd_default_password_path = os.path.join(WAZUH_PATH, 'etc', 'authd.pass')
ip_name_configuration_tests = load_tests(os.path.join(test_data_path, 'ip_name_tests.yaml'))

DEFAULT_FORCE_INSERT = 'yes'
DEFAULT_USE_USER_IP = 'no'
DEFAULT_USE_PASSWORD = 'no'
DEFAULT_TEST_PASSWORD = 'TopSecret'
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


   
def clean_client_keys_file(): 
    try:
        client_file = open(client_keys_path, 'w')
        client_file.close()        
    except IOError as exception:
        raise

    

def read_random_pass():
    osseclog_path = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    passw = None
    try:
        with open(osseclog_path, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:
                if "Random password" in line:
                    passw = line.split()[-1]
            log_file.close()        
    except IOError as exception:
        raise
    return passw

def read_hostname():
    return socket.gethostname()
    

def reset_password(set_password):
    #in case of random pass, remove /etc/authd.pass
    if set_password and set_password == 'random':
        try:
            os.remove(authd_default_password_path)
        except FileNotFoundError:
            pass
        except IOError:
            raise
    #in case of defined pass, set predefined pass in  /etc/authd.pass
    elif set_password and set_password == 'defined':
        # Write authd.pass
        try:
            with open(authd_default_password_path, 'w') as pass_file:
                pass_file.write(DEFAULT_TEST_PASSWORD)
                pass_file.close()
        except IOError as exception:
            raise



def override_wazuh_conf(configuration, set_password):
    # Stop Wazuh
    control_service('stop')
     # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)

    #reset_client_keys
    clean_client_keys_file()
    #reset password
    reset_password(set_password)

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
                #discard endline because response finalize with "'\n\n" character and client.keys only with "\n"
                if line[:-1] in response:
                    client_file.close()
                    return True
    except IOError as exception:
        raise
    return False

# Stop Wazuh
control_service('stop')
 
#reset_client_keys
clean_client_keys_file()

# Start Wazuh
control_service('start')

"""Wait until agentd has begun"""
def callback_agentd_startup(line):
    if 'Accepting connections on port 1515' in line:
        return line
    return None

log_monitor = FileMonitor(LOG_FILE_PATH)
log_monitor.start(timeout=30, callback=callback_agentd_startup)
    
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
    #setup the password enviroment to password test
    set_password = None
    test_case = ip_name_configuration_tests[test_index]['test_case']
    try:
        if ip_name_configuration_tests[test_index]['USE_PASSWORD'] == 'yes':
            set_password = 'defined'
            if ip_name_configuration_tests[test_index]['random_pass'] == 'yes':
                set_password = 'random'                
    except KeyError:
        pass
    
    override_wazuh_conf(get_configuration, set_password)
    for config in test_case:
        #clean_client_keys_file()
        address, family, connection_protocol = receiver_sockets_params[0]
        expect = config['expect']

        #insert previous agent to force repeated case
        try:
            if config['insert_prev_agent_same_name'] == "yes":
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
                try:
                    SSL_socket_prev.send(config['insert_prev_agent'], size=False)
                except KeyError:
                    SSL_socket_prev.send(config['input'], size=False)
                
                if expect == 'output':
                    # Prev output is expected
                    expected = "OSSEC K:'"
                    if expected:
                        response = SSL_socket_prev.receive().decode()
                        assert response, 'Failed connection previous insert for {}: {}'.format(ip_name_configuration_tests[test_index]['name'], config['input'])
                        assert response[:len(expected)] == expected, "Failed response previous '{}': Input: {}".format(ip_name_configuration_tests[test_index]['name'], config['input'])
                        if expected == "OSSEC K:'":
                            time.sleep(0.5)
                            assert check_client_keys_file(response) == True, "Failed test case '{}' checking previous client.keys : Input: {}".format(ip_name_configuration_tests[test_index]['name'], config['input'])
                SSL_socket_prev.close()
        except KeyError:
            pass
        

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

        #in case of test random and correct password register, read the random pass generated by os_authd and insert in query
        #in case of test random and wrong password keep the password of the original query
        if set_password and set_password == 'random':
            try:
                if config['insert_random_pass_in_query'] == 'yes':
                    config['input'] = config['input'].format(read_random_pass())
            except KeyError:
                pass
            except IndexError:
                raise

        try:
            if config['insert_hostname_in_query'] == 'yes':
                config['input'] = config['input'].format(read_hostname())
                config['output'] = config['output'].format(read_hostname())
        except KeyError:
            pass
        except IndexError:
            raise
            

        SSL_socket.send(config['input'], size=False)
        if expect == 'output':
            # Output is expected
            expected = config['output']
            if expected:
                response = SSL_socket.receive().decode()
                assert response, "Failed connection stage '{}'': '{}'".format(ip_name_configuration_tests[test_index]['name'], config['input'])
                assert response[:len(expected)] == expected, "Failed test case '{}': Input: {}".format(ip_name_configuration_tests[test_index]['name'], config['input'])
                if expected == "OSSEC K:'":
                    time.sleep(0.5)
                    assert check_client_keys_file(response) == True, "Failed test case '{}' checking client.keys : Input: {}".format(ip_name_configuration_tests[test_index]['name'], config['input'])
    return