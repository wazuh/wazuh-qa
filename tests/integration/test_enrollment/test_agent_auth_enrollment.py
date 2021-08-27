# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import ssl
import subprocess
import yaml
import time

from wazuh_testing.tools.configuration import load_wazuh_configurations
#from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.monitoring import QueueMonitor
from conftest import *

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514


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
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))
params = [{'SERVER_ADDRESS': SERVER_ADDRESS, }]
metadata = [{}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

LAST_MESSAGE = None
CURRENT_TEST_CASE = {}

def check_log_error_conf(msg):
    with open(LOG_FILE_PATH, 'r') as log_file:
        lines = log_file.readlines()
        for line in lines:
            if msg in line:
                return line
    return None

def receiver_callback(received):
    global LAST_MESSAGE
    LAST_MESSAGE = received.decode()
    socket_listener.event.set()
    return 'ERROR'

socket_listener = ManInTheMiddle(address=(SERVER_ADDRESS, 1515), family='AF_INET',
                                              connection_protocol='SSL', func=receiver_callback)

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

def launch_agent_auth(configuration):
    parse_configuration_string(configuration)
    parser = AgentAuthParser(server_address=SERVER_ADDRESS, BINARY_PATH=AGENT_AUTH_BINARY_PATH,
                             sudo=True if platform.system() == 'Linux' else False)
    if configuration.get('agent_name'):
        parser.add_agent_name(configuration.get("agent_name"))
    if configuration.get('agent_address'):
        parser.add_agent_adress(configuration.get("agent_address"))
    if configuration.get('auto_method') == 'yes':
        parser.add_auto_negotiation()
    if configuration.get('ssl_cipher'):
        parser.add_ciphers(configuration.get('ssl_cipher'))
    if configuration.get('server_ca_path'):
        parser.add_manager_ca(configuration.get('server_ca_path'))
    if configuration.get('agent_key_path'):
        parser.add_agent_certificates(configuration.get('agent_key_path'), configuration.get('agent_certificate_path'))
    if configuration.get('use_source_ip'):
        parser.use_source_ip()
    if configuration.get('password'):
        parser.add_password(configuration['password']['value'], isFile=(configuration['password']['type'] == 'file'),
                            path=AUTHDPASS_PATH)
    else:
        parser.add_password(None, isFile=True, path=AUTHDPASS_PATH)
    if configuration.get('groups'):
        parser.add_groups(configuration.get('groups'))

    out = subprocess.Popen(parser.get_command(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out.communicate()

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="function")
def configure_socket_listener(request):
    socket_listener.start()
    socket_listener.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2,
                                                   certificate='/var/ossec/etc/manager.cert',
                                                   keyfile='/var/ossec/etc/manager.key',
                                                   cert_reqs=ssl.CERT_OPTIONAL)
    while not socket_listener.queue.empty():
        socket_listener.queue.get_nowait()
    socket_listener.event.clear()
    yield
    socket_listener.shutdown()

@pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.fixture(scope="function")
def set_keys(request, test_case):
    keys = test_case.get('pre_existent_keys', [])
    if not keys:
        return
    # Write keys
    try:
        with open(CLIENT_KEYS_PATH, "w") as keys_file:
            for key in keys:
                keys_file.write(key + '\n')
            keys_file.close()
    except IOError as exception:
        raise



@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_auth_enrollment(configure_socket_listener, configure_environment, set_keys, test_case: list):
    global CURRENT_TEST_CASE
    global LAST_MESSAGE
    LAST_MESSAGE = None
    CURRENT_TEST_CASE = test_case


    if 'agent-auth' in test_case.get("skips", []):
        pytest.skip("This test does not apply to agent-auth")

    launch_agent_auth(test_case.get('configuration', {}))
    if 'expected_error' in CURRENT_TEST_CASE:
        assert check_log_error_conf(test_case.get('expected_error')) != None, \
            'Expected error log doesn´t occurred'
    else:
        while not LAST_MESSAGE:
            time.sleep(1)
        result = LAST_MESSAGE
        assert result == test_case['message']['expected'].format(**DEFAULT_VALUES),  \
            'Expected enrollment request message does not match'


    return
