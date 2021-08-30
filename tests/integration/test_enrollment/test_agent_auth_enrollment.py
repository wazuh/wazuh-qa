# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import ssl
import subprocess
import yaml
import time

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.monitoring import QueueMonitor
from conftest import *

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'

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

def receiver_callback(received):
    if len(received) == 0:
        return b""

    global LAST_MESSAGE
    LAST_MESSAGE = received.decode()
    socket_listener.event.set()
    response = CURRENT_TEST_CASE['message']['response'].format(**DEFAULT_VALUES).encode()
    return response

def get_last_message():
    global LAST_MESSAGE
    import time
    timeout = time.time() + 20 # 20 seconds timeout
    while not LAST_MESSAGE and time.time() <= timeout:
        pass
    return LAST_MESSAGE

def clear_last_message():
    global LAST_MESSAGE
    LAST_MESSAGE = None

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

socket_listener = ManInTheMiddle(address=(SERVER_ADDRESS, 1515), family='AF_INET',
                                              connection_protocol='SSL', func=receiver_callback)

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="function")
def configure_socket_listener():
    socket_listener.start()
    socket_listener.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2,
                                                   certificate='/var/ossec/etc/manager.cert',
                                                   keyfile='/var/ossec/etc/manager.key',
                                                   options=None,
                                                   cert_reqs=ssl.CERT_OPTIONAL)

    while not socket_listener.queue.empty():
        socket_listener.queue.get_nowait()
    socket_listener.event.clear()

    yield
    socket_listener.shutdown()

@pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.fixture(scope="function")
def set_keys(test_case):
    keys = test_case.get('pre_existent_keys', [])
    if not keys:
        return
    # Write keys
    try:
        with open(CLIENT_KEYS_PATH, "w") as keys_file:
            for key in keys:
                keys_file.writelines(key)
            keys_file.close()
    except IOError as exception:
        raise

@pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.fixture(scope="function")
def set_test_case(test_case):
    global CURRENT_TEST_CASE
    CURRENT_TEST_CASE = test_case

@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_auth_enrollment(set_test_case, configure_socket_listener, configure_environment, set_keys):

    if 'agent-auth' in CURRENT_TEST_CASE.get("skips", []):
        pytest.skip("This test does not apply to agent-auth")

    control_service('stop', daemon='wazuh-agentd')
    clear_last_message()
    launch_agent_auth(CURRENT_TEST_CASE.get('configuration', {}))

    if 'expected_error' in CURRENT_TEST_CASE:
        try:
            log_monitor = FileMonitor(LOG_FILE_PATH)
            log_monitor.start(timeout=120, callback=lambda x: wait_until(x, CURRENT_TEST_CASE.get('expected_error')))
        except TimeoutError as err:
            assert False, f'Expected error log doesn´t occurred'
    else:
        result = get_last_message()
        assert result != None, "Enrollment request message never arrived"
        assert result == CURRENT_TEST_CASE['message']['expected'].format(**DEFAULT_VALUES),  \
               'Expected enrollment request message does not match'

    return
