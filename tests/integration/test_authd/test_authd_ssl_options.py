# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import ssl
import time

import pytest
import yaml
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

def load_tests(path):
    """ Loads a yaml file from a path
    Returns
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
ssl_configuration_tests = load_tests(os.path.join(test_data_path, 'enroll_ssl_options_tests.yaml'))

# manager.conf configurations
DEFAULT_CIPHERS = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
DEFAULT_AUTO_NEGOTIATE = 'no'
conf_params = {'CIPHERS': [], 'SSL_AUTO_NEGOTIATE': []}

for case in ssl_configuration_tests:
    conf_params['CIPHERS'].append(case.get('CIPHERS', DEFAULT_CIPHERS))
    conf_params['SSL_AUTO_NEGOTIATE'].append(case.get('SSL_AUTO_NEGOTIATE', DEFAULT_AUTO_NEGOTIATE))

p, m = generate_params(extra_params=conf_params, modes=['scheduled'] * len(ssl_configuration_tests))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Certifcates configurations


# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
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

    time.sleep(1)
    # Start Wazuh
    control_service('start', daemon='wazuh-authd')

    """Wait until agentd has begun"""

    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)
    time.sleep(1)


def test_ossec_auth_configurations(get_configuration, configure_environment, configure_sockets_environment):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_cases, dict with following keys:
            - expect: What we are expecting to happen
                1. open_error: Should fail when trying to do ssl handshake
                2. output: Expects an output message from the manager
            - ciphers: Value for ssl ciphers
            - protocol: Value for ssl protocol
            - input: message that will be tried to send to the manager
            - output: expected response (if any)
    """
    current_test = get_current_test()

    test_case = ssl_configuration_tests[current_test]['test_case']
    override_wazuh_conf(get_configuration)
    for config in test_case:
        address, family, connection_protocol = receiver_sockets_params[0]
        SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol,
                                      open_at_start=False)
        ciphers = config['ciphers']
        protocol = config['protocol']
        SSL_socket.set_ssl_configuration(ciphers=ciphers, connection_protocol=protocol)
        expect = config['expect']
        try:
            SSL_socket.open()
        except ssl.SSLError as exception:
            if expect == 'open_error':
                # We expected the error here, check message
                assert config['error'] in str(exception), 'Expected message does not match!'
                continue
            else:
                # We did not expect this error, fail test
                raise
        SSL_socket.send(config['input'], size=False)
        if expect == 'output':
            # Output is expected
            expected = config['output']
            if expected:
                response = SSL_socket.receive().decode()
                assert response, 'Failed connection stage {}: {}'.format(test_case.index(config) + 1, config['stage'])
                assert response[:len(expected)] == expected, \
                    'Failed test case stage {}: {}'.format(test_case.index(config) + 1, config['stage'])

    return
