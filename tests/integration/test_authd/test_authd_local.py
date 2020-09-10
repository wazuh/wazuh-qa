# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import socket
import ssl
import subprocess
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
#TODO Move to utils
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.monitoring import FileMonitor
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
message_tests = load_tests(os.path.join(test_data_path, 'local_enroll_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []
ls_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'auth'))
receiver_sockets_params = [(ls_sock_path, 'AF_UNIX', 'TCP')]

#TODO Replace or delete
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('ossec-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
# Tests

@pytest.fixture(scope="function", params=message_tests)
def set_up_groups(request):
    groups = request.param.get('groups', [])
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])
    yield request.param
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

@pytest.fixture(scope="module")
def clean_client_keys_file():
    client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
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
    

def test_ossec_auth_messages(clean_client_keys_file, get_configuration, set_up_groups, configure_environment,
                             configure_mitm_environment, connect_to_sockets_module, wait_for_agentd_startup):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """       
    test_case = set_up_groups['test_case']
    for stage in test_case:
        # Reopen socket (socket is closed by maanger after sending message with client key)        
        receiver_sockets[0].open()        
        expected = stage['output']       
        message = stage['input']
        receiver_sockets[0].send(stage['input'], size=True)
        response = receiver_sockets[0].receive(size=True).decode()
        assert response[:len(expected)] == expected, \
               'Failed test case {}: Response was: {} instead of: {}'.format \
               (test_case.index(stage) + 1, response, expected)
