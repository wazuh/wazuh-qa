# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import subprocess
import yaml 

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.enrollment import EnrollmentSimulator
from wazuh_testing.tools.monitoring import QueueMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.fim import generate_params
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
SERVER_KEY_PATH = '/etc/manager.key'
SERVER_CERT_PATH = '/etc/manager.cert'
INSTALLATION_FOLDER = '/var/ossec/bin/'


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
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')

#params = [{'SERVER_ADDRESS': SERVER_ADDRESS,}, {'PORT': REMOTED_PORT,},]

conf_params = {'SERVER_ADDRESS' : [], 'REMOTED_PORT' : [], 'AGENT_NAME' : []}
DEFAULT_AGENT_NAME = 'test_agent'

for case in tests:
    conf_params['SERVER_ADDRESS'].append(case.get('SERVER_ADDRESS', SERVER_ADDRESS))
    conf_params['REMOTED_PORT'].append(case.get('REMOTED_PORT', REMOTED_PORT))
    conf_params['AGENT_NAME'].append(case.get('AGENT_NAME', DEFAULT_AGENT_NAME))
    

p, m = generate_params(extra_params=conf_params, modes=['scheduled']*len(tests))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

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

def check_client_keys_file(response):
    try:
        with open(client_keys_path) as client_file:
            client_line = client_file.readline()
            #check format key 4 items (id name ip key)
            if len(client_line.split(" ")) != 4:
                client_file.close()
                return False
            #discard \n character
            elif client_line[:-1] in response:
                client_file.close()
                return True
            else:
                client_file.close()
                return False
    except IOError as exception:
        raise
    client_file.close()
    return False

def clean_client_keys_file(): 
    try:
        client_file = open(client_keys_path, 'w')
        client_file.close()        
    except IOError as exception:
        raise

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop')
    # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)

    #reset_client_keys
    clean_client_keys_file()
    #reset password
    #reset_password(set_password)

    # Start Wazuh
    control_service('start')

@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_agentd_enrollment(get_configuration, configure_enrollment_server, configure_environment, test_case: list):
    print(f'Test: {test_case["name"]}')
    enrollment_server.clear()
    override_wazuh_conf(get_configuration)
    #configuration = test_case.get('configuration', {})
    results = monitored_sockets[0].get_results(callback=(lambda y: [x.decode() for x in y]), timeout=1, accum_results=1)
    assert results[0] == test_case['enrollment']['expected_request'], 'Expected enrollment request message does not match'
    #assert results[1] == test_case['enrollment']['response'], 'Expected response message does not match'
    assert check_client_keys_file(test_case['enrollment']['response']) == True, 'Client key does not match'
    return