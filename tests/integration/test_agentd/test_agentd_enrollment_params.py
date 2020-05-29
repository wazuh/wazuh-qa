# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import subprocess
import yaml
import socket
import time
import pdb

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.enrollment import EnrollmentSimulator
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.fim import generate_params
from conftest import DEFAULT_VALUES, SERVER_KEY_PATH, SERVER_CERT_PATH, build_expected_request, clean_client_keys_file, check_client_keys_file, clean_password_file, \
    configure_enrollment, AgentAuthParser
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
INSTALLATION_FOLDER = WAZUH_PATH

def load_tests(path):
    """ Loads a yaml file from a path 
    Retrun 
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))

#params = [{'SERVER_ADDRESS': SERVER_ADDRESS,}, {'PORT': REMOTED_PORT,},]

params = [{'SERVER_ADDRESS': SERVER_ADDRESS,}]
metadata = [{}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

enrollment_server = EnrollmentSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORT, key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def configure_enrollment_server(request):
    enrollment_server.start()
    global monitored_sockets
    monitored_sockets = [QueueMonitor(x) for x in enrollment_server.queues]

    yield

    enrollment_server.shutdown()

def clean_log_file(): 
    try:
        client_file = open(LOG_FILE_PATH, 'w')
        client_file.close()        
    except IOError as exception:
        raise

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop', daemon="ossec-agentd")

    
    # Configuration for testing
    temp = get_temp_yaml(configuration)
    conf = load_wazuh_configurations(temp, __name__,)
    os.remove(temp)
    
    
    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)

    
    #reset_client_keys
    clean_client_keys_file()
    clean_log_file()
    clean_password_file()
    if configuration.get('password'):
        parser = AgentAuthParser()
        parser.add_password(password = configuration['password']['value'], isFile = True, path = configuration.get('authorization_pass_path'))
    #reset password
    #reset_password(set_password)

    # Start Wazuh
    control_service('start', daemon="ossec-agentd")

def get_temp_yaml(param):
    temp = os.path.join(test_data_path,'temp.yaml')
    with open(configurations_path , 'r') as conf_file:
        auto_enroll_conf = {'auto_enrollment' : {'elements' : []}}
        for elem in param:
            if elem == 'password':
                continue
            auto_enroll_conf['auto_enrollment']['elements'].append({elem : {'value': param[elem]}})
        print(auto_enroll_conf)
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(auto_enroll_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp

def check_time_to_connect(timeout):
    """Wait until client try connect"""
    def wait_connect(line):
        if 'Trying to connect to server' in line:
            return line
        return None
    initial_time = time.time()
    log_monitor = FileMonitor(LOG_FILE_PATH)
    try:
        log_monitor.start(timeout=timeout + 2, callback=wait_connect)
    except TimeoutError:
        return -1
    elapsed_time = time.time() - initial_time
    return elapsed_time
    
        


@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_agentd_enrollment(configure_enrollment_server, configure_environment, test_case: list):
    print(f'Test: {test_case["name"]}')
    if 'ossec-agentd' in test_case.get("skips", []):
        pytest.skip("This test does not apply to ossec-agentd")
    configuration = test_case.get('configuration', {})
    configure_enrollment(test_case.get('enrollment'), enrollment_server, configuration.get('agent_name'))

    try:
        override_wazuh_conf(configuration)
    except Exception as err:
        if not test_case.get('enrollment',{}).get('response'):
            # Expected to happen
            return
        else:
            raise AssertionError(f'Configuration error at ossec.conf file')
    
    if configuration.get('delay_after_enrollment') and test_case.get('enrollment',{}).get('response'):
        time_delay = configuration.get('delay_after_enrollment')
        elapsed = check_time_to_connect(time_delay)
        assert ((time_delay-2) < elapsed) and (elapsed < (time_delay+2)), 'Expected elapsed time between enrollment and connect does not match'
    
    #configuration = test_case.get('configuration', {})
    results = monitored_sockets[0].get_results(callback=(lambda y: [x.decode() for x in y]), timeout=1, accum_results=1)
    if test_case.get('enrollment') and test_case['enrollment'].get('response'):
        #import pdb; pdb.set_trace()
        assert results[0] == build_expected_request(configuration), 'Expected enrollment request message does not match'
        assert results[1] == test_case['enrollment']['response'].format(**DEFAULT_VALUES), 'Expected response message does not match'
        assert results[1] == check_client_keys_file(), 'Client key does not match'
    else:
        assert len(results) == 0, 'Enrollment message was not expected!'
    return