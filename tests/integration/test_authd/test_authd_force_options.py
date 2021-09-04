# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
from wazuh_testing.tools.monitoring import SocketController, FileMonitor, callback_authd_startup
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
authd_default_password_path = os.path.join(WAZUH_PATH, 'etc', 'authd.pass')
force_options_tests = load_tests(os.path.join(test_data_path, 'test_authd_force_options.yaml'))

DEFAULT_FORCE_INSERT = 'yes'
DEFAULT_USE_USER_IP = 'no'
CLIENT_KEY_ENTRY_LEN = 4

conf_params = {'USE_SOURCE_IP': [], 'FORCE_INSERT': []}

for case in force_options_tests:
    conf_params['USE_SOURCE_IP'].append(case.get('USE_SOURCE_IP', DEFAULT_USE_USER_IP))
    conf_params['FORCE_INSERT'].append(case.get('FORCE_INSERT', DEFAULT_FORCE_INSERT))

p, m = generate_params(extra_params=conf_params, modes=['scheduled'] * len(force_options_tests))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Variables
log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
hostname = socket.gethostname()

# fixtures

test_index = 0


def get_current_test():
    global test_index
    current = test_index
    test_index += 1
    return current


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop', daemon='wazuh-authd')
    time.sleep(1)
    check_daemon_status(running=False, daemon='wazuh-authd')
    truncate_file(LOG_FILE_PATH)

    # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)

    # reset_client_keys
    truncate_file(client_keys_path)

    time.sleep(1)
    # Start Wazuh
    control_service('start', daemon='wazuh-authd')

    """Wait until authd has begun"""

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_authd_startup)
    time.sleep(1)


def check_client_keys_file(response):
    try:
        with open(client_keys_path) as client_file:
            client_lines = client_file.readlines()
            for line in client_lines:
                # discard endline because response finalize with "'\n\n" character and client.keys only with "\n"
                if line[:-1] in response:
                    client_file.close()
                    return True
    except IOError as exception:
        raise
    return False


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


# Initial clean client_keys file
# Stop Wazuh
control_service('stop')

# reset_client_keys
truncate_file(client_keys_path)

# Start Wazuh
control_service('start')

"""Wait until authd has begun"""

log_monitor = FileMonitor(LOG_FILE_PATH)
log_monitor.start(timeout=30, callback=callback_authd_startup)


# @pytest.mark.parametrize('test_case', [case['test_case'] for case in ssl_configuration_tests])
def test_authd_force_options(get_configuration, configure_environment, configure_sockets_environment):
    """Check that every input message in authd port generates the adequate output

    Every test case is defined the following way:
        - input: message that will be tried to send to the manager
        - output: expected response
        - insert_prev_agent: yes or no (for duplicated ip or name cases)
            1) if insert_prev_agent_custom is present: previous input message is overwrite by the custom message
                (insert_prev_agent_custom: "OSSEC A:'user0' IP:'10.10.10.10'")
            2) if insert_prev_agent_custom is not present: send the masage equals to input
        - insert_random_pass_in_query:
            "yes" if is needed add random pass to input query (for register with random pass cases)
        - insert_hostname_in_query:
            "yes" if is present add host name to input message
    """
    current_test = get_current_test()
    test_case = force_options_tests[current_test]['test_case']

    override_wazuh_conf(get_configuration)
    for config in test_case:

        # insert previous agent to force repeated case
        try:
            if config['insert_prev_agent'] == "yes":
                try:
                    response = send_message(config['insert_prev_agent_custom'])
                except KeyError:
                    response = send_message(config['input'])

                # Prev output is expected
                expected = "OSSEC K:'"
                assert response, \
                    'Failed connection previous insert for {}: {}'.format \
                        (force_options_tests[current_test]['name'], config['input'])
                assert response[:len(expected)] == expected, \
                    "Failed response previous '{}': Input: {}".format \
                        (force_options_tests[current_test]['name'], config['input'])
                if expected == "OSSEC K:'":
                    time.sleep(0.5)
                    assert check_client_keys_file(response) == True, \
                        "Failed test case '{}' checking previous client.keys : Input: {}".format \
                            (force_options_tests[current_test]['name'], config['input'])
        except KeyError:
            pass

        try:
            if config['insert_hostname_in_query'] == 'yes':
                config['input'] = config['input'].format(hostname)
                config['output'] = config['output'].format(hostname)
        except KeyError:
            pass
        except IndexError:
            raise

        # Output is expected
        expected = config['output']
        response = send_message(config['input'])
        assert response, "Failed connection stage '{}'': '{}'".format \
            (force_options_tests[current_test]['name'], config['input'])
        if response[:len(expected)] != expected:
            if config.get('expected_fail') == 'yes':
                pytest.xfail("Test expected to fail by configuration")
            else:
                raise AssertionError("Failed test case '{}': Input: {}".format \
                                         (force_options_tests[current_test]['name'], config['input']))

        # if expect a key check with client.keys file
        if expected[:len("OSSEC K:'")] == "OSSEC K:'":
            time.sleep(0.5)
            if "/32" in response:
                response = response.replace("/32", "")
            assert check_client_keys_file(response) == True, \
                "Failed test case '{}' checking client.keys : Input: {}".format \
                    (force_options_tests[current_test]['name'], config['input'])
    return
