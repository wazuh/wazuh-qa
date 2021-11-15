'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check the different errors that may appear by modifying 
       the path of the configurable executable (exec_path).

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

import pytest
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import validate_authd_logs, override_wazuh_conf

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
fetch_keys_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files')
message_tests = read_yaml(os.path.join(test_data_path, 'test_key_request_exec_path.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
local_internal_options = {'authd.debug': '2'}
filename = "fetch_keys.py"

shutil.copy(os.path.join(fetch_keys_path, filename), os.path.join("/tmp", filename))

DEFAULT_EXEC_PATH = '/var/ossec/framework/python/bin/python3 /tmp/fetch_keys.py'
conf_params = {'EXEC_PATH': []}

for case in message_tests:
    conf_params['EXEC_PATH'].append(case.get('EXEC_PATH', DEFAULT_EXEC_PATH))

p, m = generate_params(extra_params=conf_params, modes=['scheduled'] * len(message_tests))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Variables
kreq_sock_path = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest')
log_monitor_paths = [LOG_FILE_PATH]
receiver_sockets_params = [(kreq_sock_path, 'AF_UNIX', 'UDP')]
test_case_ids = [f"{test_case['name'].lower().replace(' ', '-')}" for test_case in message_tests]

# TODO Replace or delete
monitored_sockets_params = [('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Tests
test_index = 0

def get_current_test():
    """
    Get the current test case.
    """
    global test_index
    current = test_index
    test_index += 1
    return current

@pytest.fixture(scope="module", params=configurations, ids=test_case_ids)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

def test_key_request_exec_path(get_configuration, configure_local_internal_options_module, configure_environment, configure_sockets_environment, 
                                connect_to_sockets_function, tear_down):
    '''
    description: 
        Checks that every input message on the key request port with different exec_path configuration
        shows the corresponding error in the manager logs.

    wazuh_min_version: 4.4.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get the configuration of the test.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - configure_sockets_environment_function:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets at function scope.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - tear_down:
            type: fixture
            brief: Cleans the client.keys file.

    assertions:
        - The exec_path must be configured correctly
        - The script works as expected

    input_description:
        Different test cases are contained in an external YAML file (test_key_request_exec_path.yaml) which
        includes the different possible key requests with different configurations and the expected responses.

    expected_log:
        - Key request responses on 'authd' logs.
    '''
    current_test = get_current_test()
    case = message_tests[current_test]['test_case']
    # Overwrites the configuration with the values ​​set in the YAML file
    override_wazuh_conf(get_configuration)
    key_request_sock = receiver_sockets[0]

    for stage in case:
        # Reopen socket (socket is closed by manager after sending message with client key)
        key_request_sock.open()
        message = stage['input']
        key_request_sock.send(message, size=False)
        response = stage.get('log', [])
        # Monitor expected log messages
        validate_authd_logs(response)
