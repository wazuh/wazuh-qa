'''
brief: This module verifies the correct behavior of the enrollment daemon authd under different messages
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

metadata:
    component:
        - Manager
    modules:
        - Authd
    daemons:
        - authd
    operating_system:
        - Ubuntu
        - CentOS
    tiers:
        - 0
    tags:
        - Enrollment
        - Authd
'''

import os
import subprocess
import time

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations


def load_tests(path):
    """Loads a yaml file from a path
    Args:
        path (str): path to the file.

    Returns:
        dict: dictionary containing the test info.
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = load_tests(os.path.join(test_data_path, 'authd_key_hash.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Tests

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


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


@pytest.fixture(scope="module", params=message_tests)
def set_up_groups_keys(request):
    client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
    # Stop Wazuh
    control_service('stop')

    keys = request.param.get('pre_existent_keys', [])
    # Write keys
    try:
        with open(client_keys_path, "w") as keys_file:
            for key in keys:
                keys_file.write(key + '\n')
            keys_file.close()
    except IOError as exception:
        raise

    # Start Wazuh
    control_service('start')

    groups = request.param.get('groups', [])
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])

    yield request.param

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])

    clean_client_keys_file()


def test_ossec_auth_messages_with_key_hash(set_up_groups_keys, get_configuration, configure_environment,
                                           configure_sockets_environment, connect_to_sockets_module,
                                           wait_for_agentd_startup):
    """
        test_logic:
            "Check that every input message in authd port generates the adequate output"

        checks:
            - The received output must match with expected
            - The enrollment messages are parsed as expected
            - The agent keys are denied if the hash is the same than the manager's

        Raises:
            - ConnectionResetError: if wazuh-authd does not send the response to the agent through the socket.
            - AssertionError: if the response does not match the expected message.
    """
    test_case = set_up_groups_keys['test_case']

    for stage in test_case:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']
        message = stage['input']
        receiver_sockets[0].send(stage['input'], size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        assert response[:len(expected)] == expected, \
            'Failed test case {}: Response was: {} instead of: {}' \
            .format(set_up_groups_keys['name'], response, expected)
