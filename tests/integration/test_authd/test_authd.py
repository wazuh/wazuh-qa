'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-authd' daemon correctly handles the enrollment requests,
       generating consistent responses to the requests received on its IP v4 network socket.
       The 'wazuh-authd' daemon can automatically add a Wazuh agent to a Wazuh manager and provide
       the key to the agent. It is used along with the 'agent-auth' application.

tier: 0

modules:
    - authd

components:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db
    - wazuh-modulesd

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-authd.html
    - https://documentation.wazuh.com/current/user-manual/reference/tools/agent_groups.html

tags:
    - enrollment
'''
import os
import subprocess
import time

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = read_yaml(os.path.join(test_data_path, 'enroll_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

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


def test_ossec_auth_messages(get_configuration, set_up_groups, configure_environment, configure_sockets_environment,
                             clean_client_keys_file_module, restart_authd, wait_for_authd_startup_module,
                             connect_to_sockets_module):
    '''
    description: Check if when the `wazuh-authd` daemon receives different kinds of enrollment requests,
                 it responds appropriately to them. In this case, the enrollment requests
                 are sent to an IP v4 network socket.

    wazuh_min_version: 4.2

    parameters:
        - clean_client_keys_file:
            type: fixture
            brief: Delete the agent keys stored in the `client.keys` file.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - set_up_groups:
            type: fixture
            brief: Create a testing group for agents and provide the test case list.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of `connect_to_sockets` fixture.
        - wait_for_agentd_startup:
            type: fixture
            brief: Wait until the `wazuh-agentd` has begun.

    assertions:
        - Verify that the response messages are consistent with the enrollment requests received.

    input_description: Different test cases are contained in an external `YAML` file (enroll_messages.yaml)
                       that includes enrollment events and the expected output.

    expected_output:
        - Multiple values located in the `enroll_messages.yaml` file.

    tags:
        - keys
        - ssl
    '''
    test_case = set_up_groups['test_case']
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
            'Failed test case {}: Response was: {} instead of: {}'.format(set_up_groups['name'], response, expected)
