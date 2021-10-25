'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: This module verifies the correct behavior of the enrollment daemon authd under different messages
tier:
    0
modules:
    - Authd
components:
    - manager
daemons:
    - Authd
path:
    /tests/integration/test_authd/test_authd_key_hash.py
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
import subprocess
import time

import pytest
from wazuh_testing.tools import CLIENT_KEYS_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml, truncate_file
from wazuh_testing.authd import DAEMON_NAME

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = read_yaml(os.path.join(test_data_path, 'authd_key_hash.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables

log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Tests

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """
    Get configurations from the module
    """
    yield request.param


@pytest.fixture(scope="module", params=message_tests)
def set_up_groups_keys(request):
    """
    Set pre-existent groups and keys.
    """
    # Stop Wazuh
    control_service('stop', DAEMON_NAME)

    keys = request.param.get('pre_existent_keys', [])
    # Write keys
    try:
        with open(CLIENT_KEYS_PATH, "w") as keys_file:
            for key in keys:
                keys_file.write(key + '\n')
            keys_file.close()
    except IOError as exception:
        raise

    # Start Wazuh
    control_service('start', DAEMON_NAME)

    groups = request.param.get('groups', [])
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])

    yield request.param

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])


def test_ossec_auth_messages_with_key_hash(get_configuration, configure_environment,  configure_sockets_environment,
                                           clean_client_keys_file_module, set_up_groups_keys,
                                           wait_for_authd_startup_function, connect_to_sockets_function):
    """
        description:
           "Check that every input message in authd port generates the adequate output"
        wazuh_min_version:
            4.2
        parameters:
            - get_configuration:
                type: fixture
                brief: Get the configuration of the test.
            - configure_environment:
                type: fixture
                brief: Configure a custom environment for testing.
            - configure_sockets_environment:
                type: fixture
                brief: Configure the socket listener to receive and send messages on the sockets.
            - clean_client_keys_file_module:
                type: fixture
                brief: Stops Wazuh and cleans any previus key in client.keys file at module scope.
            - set_up_groups_keys:
                type: fixture
                brief: Set pre-existent groups and keys.
            - wait_for_authd_startup_function:
                type: fixture
                brief: Waits until Authd is accepting connections.
            - connect_to_sockets_function:
                type: fixture
                brief: Bind to the configured sockets at function scope.
        assertions:
            - The received output must match with expected
            - The enrollment messages are parsed as expected
            - The agent keys are denied if the hash is the same than the manager's
        input_description:
            Different test cases are contained in an external YAML file (authd_key_hash.yaml) which includes
            the different possible registration requests and the expected responses.
        expected_output:
            - Registration request responses on Authd socket
    """
    test_case = set_up_groups_keys['test_case']

    for stage in test_case:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']
        message = stage['input']
        receiver_sockets[0].send(message, size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        assert response[:len(expected)] == expected, \
            'Failed test case {}: Response was: {} instead of: {}' \
            .format(set_up_groups_keys['name'], response, expected)
