'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: This module verifies the correct behavior of authd under different name/IP combinations
tier:
    0
modules:
    - Authd
components:
    - manager
daemons:
    - Authd
path:
    /tests/integration/test_authd/test_authd_valid_name_ip.py
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
import socket
import time
import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
test_authd_valid_name_ip_tests = read_yaml(os.path.join(test_data_path, 'test_authd_valid_name_ip.yaml'))
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables

log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
hostname = socket.gethostname()

# Fixtures


@pytest.fixture(scope='module', params=configurations, ids=[__name__])
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='module')
def clean_client_keys_file_module():
    """
    Stops Wazuh and cleans any previus key in client.keys file at module scope.
    """
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


@pytest.fixture(scope='module')
def tear_down():
    """
    Roll back the daemon and client.keys state after the test ends.
    """
    yield
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


# Test


@pytest.mark.parametrize('test_case', [case for case in test_authd_valid_name_ip_tests],
                         ids=[test_case['name'] for test_case in test_authd_valid_name_ip_tests])
def test_authd_force_options(clean_client_keys_file_module, clean_client_keys_file_function,
                             get_configuration, configure_environment, configure_sockets_environment,
                             connect_to_sockets_module, test_case, tear_down):
    """
        description:
           "Check that every input message in authd port generates the adequate output"
        wazuh_min_version:
            4.2
        parameters:
            - clean_client_keys_file_module:
                type: fixture
                brief: Stops Wazuh and cleans any previus key in client.keys file at module scope.
            - clean_client_keys_file_function:
                type: fixture
                brief: Cleans any previus key in client.keys file at function scope.
            - get_configuration:
                type: fixture
                brief: Get the configuration of the test.
            - configure_environment:
                type: fixture
                brief: Configure a custom environment for testing.
            - configure_sockets_environment:
                type: fixture
                brief: Configure the socket listener to receive and send messages on the sockets.
            - connect_to_sockets_module:
                type: fixture
                brief: Bind to the configured sockets at module scope.
            - test_case:
                type: list
                brief: List with all the test cases for the test.
            - tear_down:
                type: fixture
                brief: Roll back the daemon and client.keys state after the test ends.
        assertions:
            - The manager registers agents with valid IP and name
            - The manager rejects invalid input
        input_description:
            Different test cases are contained in an external YAML file (test_authd_valid_name_ip.yaml) which includes
            the different possible registration requests and the expected responses.
        expected_output:
            - Registration request responses on Authd socket
    """

    for stage in test_case['test_case']:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        message = stage['input']
        expected = stage['output']
        # Checking 'hostname' test case
        try:
            if stage['insert_hostname_in_query'] == 'yes':
                stage['input'] = stage['input'].format(hostname)
                stage['output'] = stage['output'].format(hostname)
        except KeyError:
            pass
        except IndexError:
            raise

        receiver_sockets[0].send(message, size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')

        if response[:len(expected)] != expected:
            if stage.get('expected_fail') == 'yes':
                pytest.xfail("Test expected to fail by configuration")
            else:
                raise AssertionError('Failed: Response is different from expected')
