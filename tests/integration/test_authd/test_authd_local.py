'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: This module verifies the correct behavior of authd under different messages in a Cluster scenario (for Master)
tier:
    0
modules:
    - Authd
components:
    - manager
daemons:
    - Authd
path:
    /tests/integration/test_authd/test_authd_local.py
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

import pytest
import yaml
import time
from wazuh_testing.tools import WAZUH_PATH, CLIENT_KEYS_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.wazuh_db import query_wdb
# TODO Move to utils
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.file import truncate_file

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = read_yaml(os.path.join(test_data_path, 'local_enroll_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []
ls_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'auth'))
receiver_sockets_params = [(ls_sock_path, 'AF_UNIX', 'TCP'), (WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]
test_case_ids = [f"{test_case['name']}" for test_case in message_tests]

# TODO Replace or delete
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Fixtures

@pytest.fixture(scope="module", params=configurations, ids=['authd_local_config'])
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope='function', params=message_tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param


@pytest.fixture(scope="function")
def set_up_groups(get_current_test_case, request):
    """
    Set pre-existent groups.
    """

    groups = get_current_test_case.get('groups', [])

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])

    yield

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])

@pytest.fixture(scope='function')
def insert_pre_existent_agents_client_keys(get_current_test_case, request):

    control_service("stop", daemon='wazuh-authd')

    agents = get_current_test_case.get('pre_existent_agents', [])

    with open(CLIENT_KEYS_PATH, "w") as keys_file:

        for agent in agents:

            if 'id' in agent:
                id = agent['id']
            else:
                id = '001'

            if 'name' in agent:
                name = agent['name']
            else:
                name = f'TestAgent{id}'

            if 'ip' in agent:
                ip = agent['ip']
            else:
                ip = 'any'

            if 'key' in agent:
                key = agent['key']
            else:
                key = 'TopSecret'

            # Write agent in client.keys
            keys_file.write(f'{id} {name} {ip} {key}\n')

    keys_file.close()

    control_service("start", daemon='wazuh-authd')


@pytest.fixture(scope='function')
def insert_pre_existent_agents_db(get_current_test_case, request):
    agents = get_current_test_case.get('pre_existent_agents', [])
    time_now = int(time.time())

    # Clean agents from DB
    command = f'global sql DELETE FROM agent WHERE id != 0'
    query_wdb(command)

    for agent in agents:
        if 'id' in agent:
            id = agent['id']
        else:
            id = '001'

        if 'name' in agent:
            name = agent['name']
        else:
            name = f'TestAgent{id}'

        if 'ip' in agent:
            ip = agent['ip']
        else:
            ip = 'any'

        if 'key' in agent:
            key = agent['key']
        else:
            key = 'TopSecret'

        if 'connection_status' in agent:
            connection_status = agent['connection_status']
        else:
            connection_status = 'never_connected'

        if 'disconnection_time' in agent and 'delta' in agent['disconnection_time']:
            disconnection_time = time_now + agent['disconnection_time']['delta']
        elif 'disconnection_time' in agent and 'value' in agent['disconnection_time']:
            disconnection_time = agent['disconnection_time']['value']
        else:
            disconnection_time = 0

        if 'registration_time' in agent and 'delta' in agent['registration_time']:
            registration_time = time_now + agent['registration_time']['delta']
        elif 'registration_time' in agent and 'value' in agent['registration_time']:
            registration_time = agent['registration_time']['value']
        else:
            registration_time = time_now

        # Write agent in global.db
        command = f'global insert-agent {{"id":{id},"name":"{name}","ip":"{ip}","date_add":{registration_time},\
                  "connection_status":"{connection_status}", "disconnection_time":"{disconnection_time}"}}'

        query_wdb(command)

    yield

    command = f'global sql DELETE FROM agent WHERE id != 0'
    query_wdb(command)

@pytest.fixture(scope='function')
def clean_authd_function():
    """
    Restart Authd.
    """
    control_service("stop", daemon='wazuh-authd')
    truncate_file(CLIENT_KEYS_PATH)
    control_service("start", daemon='wazuh-authd')

    yield

    control_service("stop", daemon='wazuh-authd')
    truncate_file(CLIENT_KEYS_PATH)
    control_service("start", daemon='wazuh-authd')


# Tests

def test_authd_local_messages(clean_authd_function, set_up_groups, insert_pre_existent_agents_db, insert_pre_existent_agents_client_keys, get_configuration,
                              configure_environment, configure_sockets_environment_function, connect_to_sockets_function,
                              wait_for_authd_startup_module, get_current_test_case):
    """
        description:
            "Check that every input message in trough local authd port generates the adequate response to worker"
        wazuh_min_version:
            4.2
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
            - The received output must match with expected
            - The enrollment messages are parsed as expected
            - The agent keys are denied if the hash is the same than the manager's
        input_description:
            Different test cases are contained in an external YAML file (local_enroll_messages.yaml) which includes
            the different possible registration requests and the expected responses.
        expected_output:
            - Registration request responses on Authd socket
    """
    case = get_current_test_case['test_case']
    for index, stage in enumerate(case):
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']
        message = stage['input']
        receiver_sockets[0].send(stage['input'], size=True)
        response = receiver_sockets[0].receive(size=True).decode()
        assert response[:len(expected)] == expected, \
            'Failed stage "{}". Response was: {} instead of: {}' \
            .format(index+1, response, expected)
