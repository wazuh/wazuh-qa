'''
brief: This module verifies the correct behavior of authd under different messages in a Cluster scenario (for Master)
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

metadata:
    component:
        - Manager
    modules:
        - Authd
        - Cluster
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
        - Master
'''

import os
import subprocess

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
# TODO Move to utils
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import load_tests

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = load_tests(os.path.join(test_data_path, 'local_enroll_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []
ls_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'auth'))
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
def set_up_groups_keys(request):
    client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')

    keys = request.param.get('pre_existent_keys', [])

    # Stop Wazuh
    control_service('stop')
    # Write keys
    try:
        # The client.keys file is cleaned always
        # but the keys are added only if pre_existent_keys has values
        with open(client_keys_path, "w") as keys_file:
            if(keys is not None):
                for key in keys:
                    keys_file.write(key + '\n')
            keys_file.close()
    except IOError as exception:
        raise

    # Starting wazuh in another fixture
    # control_service('start')

    groups = request.param.get('groups', [])
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])

    yield request.param

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])


def test_ossec_auth_messages(set_up_groups_keys, get_configuration, configure_environment,
                             configure_sockets_environment_function, connect_to_sockets_function,
                             wait_for_agentd_startup):
    """
        test_logic:
            "Check that every input message in trough local authd port generates the adequate response to worker"

        checks:
            - The received output must match with expected
            - The enrollment messages are parsed as expected
            - The agent keys are denied if the hash is the same than the manager's
    """
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
