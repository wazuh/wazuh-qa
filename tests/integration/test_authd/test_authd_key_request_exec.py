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
import shutil
import subprocess

import pytest
import yaml
import time

from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH, CLIENT_KEYS_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml, truncate_file
from wazuh_testing.authd import AUTHD_KEY_REQUEST_TIMEOUT, validate_authd_logs

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
fetch_keys_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files')
message_tests = read_yaml(os.path.join(test_data_path, 'test_key_request_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)
filename = "fetch_keys.py"

shutil.copy(os.path.join(fetch_keys_path, filename), os.path.join("/tmp", filename))

# Variables
kreq_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest'))
log_monitor_paths = [LOG_FILE_PATH]
receiver_sockets_params = [(kreq_sock_path, 'AF_UNIX', 'UDP')]
test_case_ids = [f"{test_case['name'].lower().replace(' ', '-')}" for test_case in message_tests]

# TODO Replace or delete
monitored_sockets_params = [('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Tests

@pytest.fixture(scope="module", params=configurations, ids=['key_request_exec'])
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope='function', params=message_tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param


def test_key_request_exec(configure_environment, configure_sockets_environment, connect_to_sockets_function,
                            get_current_test_case, tear_down):
    '''
    description: 

    wazuh_min_version: 4.4.0

    parameters:
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
        - The exec_path must be configured correctly
        - The script works as expected

    input_description:
        Different test cases are contained in an external YAML file (test_authd_key_request_messages.yaml) which
        includes the different possible key requests and the expected responses.

    expected_log:
        - Key request responses on 'authd' logs.
    '''
    case = get_current_test_case['test_case']
    for index, stage in enumerate(case):
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['log']
        message = stage['input']
        receiver_sockets[0].send(message, size=False)
        response = stage.get('log', [])
        validate_authd_logs(response)
        assert response == expected, 'Failed stage {}: Response was: {} instead of: {}'.format(index+1, response, expected)
