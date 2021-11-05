'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-authd' daemon correctly handles the key requests
       from agents with pre-existing IP addresses or names.

tier: 0

modules:
    - authd

components:
    - manager

daemons:
    - wazuh-authd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/agent-key-request.html

tags:
    - key_request
'''
import os
import subprocess

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH, CLIENT_KEYS_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
# TODO Move to utils
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = read_yaml(os.path.join(test_data_path, 'test_key_request_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []
ls_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest'))
receiver_sockets_params = [(ls_sock_path, 'AF_UNIX', 'TCP')]

# TODO Replace or delete
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Tests

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope="function", params=message_tests)
def set_up_keys(request):
    """
    Set pre-existent groups and keys.
    """
    keys = request.param.get('pre_existent_keys', [])

    # Stop Wazuh
    control_service('stop')
    # Write keys
    try:
        # The client.keys file is cleaned always
        # but the keys are added only if pre_existent_keys has values
        with open(CLIENT_KEYS_PATH, "w") as keys_file:
            if(keys is not None):
                for key in keys:
                    keys_file.write(key + '\n')
            keys_file.close()
    except IOError as exception:
        raise

    # Starting wazuh in another fixture
    # control_service('start')


def test_ossec_auth_key_request_exec(set_up_groups_keys, get_configuration, configure_environment,
                             configure_sockets_environment_function, connect_to_sockets_function,
                             wait_for_authd_startup_module):
    '''
    description: 

    wazuh_min_version: 4.4.0

    parameters:
        - set_up_groups_keys:
            type: fixture
            brief: Set pre-existent groups and keys.
        - get_configuration:
            type: fixture
            brief: Get the configuration of the test.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment_function:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets at function scope.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - wait_for_authd_startup_module:
            type: fixture
            brief: Waits until Authd is accepting connections.

    assertions:
        -

    input_description:
        Different test cases are contained in an external YAML file (test_authd_key_request_messages.yaml) which
        includes the different possible key requests and the expected responses.

    expected_output:
        - Key request responses on 'authd' socket.
    '''
    test_case = set_up_groups_keys['test_case']
    for stage in test_case:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']
        message = stage['input']
        receiver_sockets[0].send(stage['input'], size=True)
        response = receiver_sockets[0].receive(size=True).decode()
        assert response[:len(expected)] == expected, \
            'Failed test case "{}". Response was: {} instead of: {}' \
            .format(set_up_groups_keys['name'], response, expected)
