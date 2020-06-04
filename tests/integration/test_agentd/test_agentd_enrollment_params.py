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
import datetime

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH, WAZUH_CONF
from wazuh_testing.fim import generate_params
from conftest import *

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

authd_server = AuthdSimulator(server_address=SERVER_ADDRESS, key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def configure_authd_server(request):
    authd_server.start()
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)

    yield

    authd_server.shutdown()

def clean_log_file(): 
    try:
        client_file = open(LOG_FILE_PATH, 'w')
        client_file.close()        
    except IOError as exception:
        raise

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop')

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

    # Start Wazuh
    control_service('start')

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
        
    log_monitor = FileMonitor(LOG_FILE_PATH)
    try:
        log_monitor.start(timeout=timeout + 2, callback=wait_connect)
    except TimeoutError:
        return -1
    
    final_line = log_monitor.result()
    initial_line = None
    elapsed_time = None

    with open(LOG_FILE_PATH , 'r') as log_file:
        lines = log_file.readlines()
        #find enrollment end
        for line in lines:
            if "INFO: Valid key created. Finished." in line:
                if "INFO: Connection closed." in lines[lines.index(line) + 1]:
                    initial_line = lines[lines.index(line) + 1]
                    break
    
    if initial_line != None and final_line != None:
        form = '%H:%M:%S'
        initial_time = datetime.datetime.strptime(initial_line.split()[1], form).time()
        final_time = datetime.datetime.strptime(final_line.split()[1], form).time()
        initial_delta = datetime.timedelta(hours=initial_time.hour, minutes=initial_time.minute, seconds=initial_time.second)
        final_delta = datetime.timedelta(hours=final_time.hour, minutes=final_time.minute, seconds=final_time.second)
        elapsed_time = (final_delta - initial_delta).total_seconds()
        
    return elapsed_time

def check_log_error_conf():
    with open(LOG_FILE_PATH , 'r') as log_file:
        lines = log_file.readlines()
        for line in lines:
            if f"ERROR: (1202): Configuration error at '{WAZUH_CONF}'" in line:
                return True
    return False
    
        


@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_agentd_enrollment(configure_authd_server, configure_environment, test_case: list):
    print(f'Test: {test_case["name"]}')
    if 'ossec-agentd' in test_case.get("skips", []):
        pytest.skip("This test does not apply to ossec-agentd")
    configuration = test_case.get('configuration', {})
    parse_configuration_string(configuration)
    configure_enrollment(test_case.get('enrollment'), authd_server, configuration.get('agent_name'))
    try:
        override_wazuh_conf(configuration)
    except Exception as err:
        if not test_case.get('enrollment',{}).get('response'):
            # Expected to happen
            assert True == check_log_error_conf(), 'Expected configuration error at ossec.conf file, fail log_check'
            return
        else:
            raise AssertionError(f'Configuration error at ossec.conf file')
    
    if configuration.get('delay_after_enrollment') and test_case.get('enrollment',{}).get('response'):
        time_delay = configuration.get('delay_after_enrollment')
        elapsed = check_time_to_connect(time_delay)
        assert ((time_delay-2) < elapsed) and (elapsed < (time_delay+2)), f'Expected elapsed time between enrollment and connect does not match, should be around {time_delay} sec.'
    
    #configuration = test_case.get('configuration', {})
    results = monitored_sockets.get_results(callback=(lambda y: [x.decode() for x in y]), timeout=1, accum_results=1)
    if test_case.get('enrollment') and test_case['enrollment'].get('response'):
        #import pdb; pdb.set_trace()
        assert results[0] == build_expected_request(configuration), 'Expected enrollment request message does not match'
        assert results[1] == test_case['enrollment']['response'].format(**DEFAULT_VALUES), 'Expected response message does not match'
        assert results[1] == check_client_keys_file(), 'Client key does not match'
    else:
        assert len(results) == 0, 'Enrollment message was not expected!'
    return