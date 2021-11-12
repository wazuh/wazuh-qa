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
import time

import pytest
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf, \
    load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import validate_authd_logs
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status
from wazuh_testing.tools.file import truncate_file


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
fetch_keys_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files')
message_tests = read_yaml(os.path.join(test_data_path, 'test_key_request_exec_path.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
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

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop', daemon='wazuh-authd')
    time.sleep(1)
    check_daemon_status(running_condition=False, target_daemon='wazuh-authd')
    truncate_file(log_monitor_paths[0])

    # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)
    # Start Wazuh daemons
    time.sleep(1)
    control_service('start', daemon='wazuh-authd', debug_mode=True)

    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(log_monitor_paths[0])
    log_monitor.start(timeout=30, callback=callback_agentd_startup)
    time.sleep(1)

def test_key_request_exec_path2(get_configuration, configure_environment, configure_sockets_environment, connect_to_sockets_function,
                                tear_down):
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
    current_test = get_current_test()
    case = message_tests[current_test]['test_case']
    override_wazuh_conf(get_configuration)
    for stage in case:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        message = stage['input']
        receiver_sockets[0].send(message, size=False)
        response = stage.get('log', [])
        validate_authd_logs(response)
