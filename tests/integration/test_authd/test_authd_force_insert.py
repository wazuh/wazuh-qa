'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: This module verifies the correct behavior of the setting force_insert
tier:
    0
modules:
    - Authd
components:
    - manager
daemons:
    - Authd
path:
    /tests/integration/test_authd/test_authd_force_insert.py
os_platform
    - linux
os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial
tags:
    - Enrollment
'''

import os
import time
import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.services import control_service
from authd import validate_authd_response

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

parameters = [
    {'FORCE_INSERT': 'yes'},
    {'FORCE_INSERT': 'no'}
]

metadata = [
    {'force_insert': 'yes'},
    {'force_insert': 'no'}
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
test_authd_force_insert_yes_tests = read_yaml(os.path.join(test_data_path, 'test_authd_force_insert.yaml'))
configuration_ids = [f"Force_insert_{x['FORCE_INSERT']}" for x in parameters]
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Variables
log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Fixtures


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope='function')
def register_previous_agent(test_case):
    """
    Register agents to simulate a scenario with pre existent keys.
    """
    if 'previous_agent_name' in test_case:
        prev_agent_message = f"OSSEC A:'{test_case['previous_agent_name']}'"
        if 'previous_agent_ip' in test_case:
            prev_agent_message = f"OSSEC A:'{test_case['previous_agent_name']}' IP:'{test_case['previous_agent_ip']}'"

        receiver_sockets[0].open()
        receiver_sockets[0].send(prev_agent_message, size=False)
        timeout = time.time() + 10
        response = ''

        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')

    yield


# Test

@pytest.mark.parametrize('test_case', [case for case in test_authd_force_insert_yes_tests],
                         ids=[test_case['name'] for test_case in test_authd_force_insert_yes_tests])
def test_authd_force_options(clean_client_keys_file_module, configure_sockets_environment, configure_environment,
                             restart_authd, wait_for_authd_startup_module, connect_to_sockets_configuration,
                             register_previous_agent, tear_down, test_case, get_configuration):
    """
        description:
           "Check that every input message in authd port generates the adequate output"
        wazuh_min_version:
            4.2
        parameters:
            - clean_client_keys_file_module:
                type: fixture
                brief: Stops Wazuh and cleans any previus key in client.keys file at module scope.
            - configure_sockets_environment:
                type: fixture
                brief: Configure the socket listener to receive and send messages on the sockets.
            - configure_environment:
                type: fixture
                brief: Configure a custom environment for testing.
            - restart_authd:
                type: fixture
                brief: Restart Authd daemon to force new configurations.
            - wait_for_authd_startup_module:
                type: fixcture
                brief: Wait until Authd is accepting connections.
            - connect_to_sockets_configuration:
                type: fixture
                brief: Bind to the configured sockets at configuration scope.
            - register_previous_agent:
                type: fixture
                brief: Register agents to simulate a scenario with pre existent keys.
            - tear_down:
                type: fixture
                brief: Roll back the daemon and client.keys state after the test ends.
            - get_configuration:
                type: fixture
                brief: Get the configuration of the test.
            - test_case:
                type: list
                brief: List with all the test cases for the test.
        assertions:
            - The received output must match with expected when the setting is used
            - The agent can't have a duplicate IP or name when the setting is disabled
        input_description:
            Different test cases are contained in an external YAML file (test_authd_force_insert.yaml) which includes
            the different possible registration requests and the expected responses.
        expected_output:
            - Registration request responses on Authd socket
    """

    metadata = get_configuration['metadata']

    for stage in test_case['test_case']:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        message = stage['input']
        receiver_sockets[0].send(message, size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')

        if metadata['force_insert'] == 'no' and ('previous_agent_name' in test_case):
            expected = {'status': 'error', 'message': r'^Duplicate'}
        else:
            expected = stage['output']

        validate_authd_response(response, expected)
