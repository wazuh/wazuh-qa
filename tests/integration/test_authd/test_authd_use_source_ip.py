'''
brief: This module verifies the correct behavior of the setting use_source_ip
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
import socket
import ssl
import time
import pytest
import yaml
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file, load_tests
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

parameters = [
    {'USE_SOURCE_IP': 'yes'},
    {'USE_SOURCE_IP': 'no'}
]

metadata = [
    {'use_source_ip': 'yes'},
    {'use_source_ip': 'no'}
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
test_authd_use_source_ip_tests = load_tests(os.path.join(test_data_path, 'test_authd_use_source_ip.yaml'))
configuration_ids = [f"Use_source_ip_{x['USE_SOURCE_IP']}" for x in parameters]
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Variables

log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Functions


def send_message(message):
    address, family, connection_protocol = receiver_sockets_params[0]
    SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol)
    try:
        SSL_socket.open()
    except ssl.SSLError as exception:
        # We did not expect this error, fail test
        raise
    SSL_socket.send(message, size=False)
    response = SSL_socket.receive().decode()
    SSL_socket.close()
    return response

# Fixtures


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope='function')
def clean_client_keys_file_function():
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
def clean_client_keys_file_module():
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

@pytest.mark.parametrize('test_case', [case for case in test_authd_use_source_ip_tests],
                         ids=[test_case['name'] for test_case in test_authd_use_source_ip_tests])
def test_authd_force_options(clean_client_keys_file_module, clean_client_keys_file_function,
                             get_configuration, configure_environment, configure_sockets_environment,
                             connect_to_sockets_module, test_case, tear_down):
    """
        test_logic:
            "Check that every input message in authd port generates the adequate output"

        checks:
            - The manager uses the agent's IP as requested
            - Setting an IP overrides the configuration
            - If the IP is not defined an the setting is disabled, use 'any'
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

        if metadata['use_source_ip'] == 'yes' and test_case['ip_specified'] == 'no':
            expected = "OSSEC K:'001 user1 127.0.0.1 "
        else:
            expected = stage['output']

        assert response[:len(expected)] == expected, 'Failed: Response is different from expected'
