# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import ssl
import subprocess
import yaml
import time

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.monitoring import QueueMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf
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

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
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

def get_temp_yaml(param):
    temp = os.path.join(test_data_path, 'temp.yaml')
    with open(configurations_path, 'r') as conf_file:
        enroll_conf = {'enrollment': {'elements': []}}
        for elem in param:
            if elem == 'password':
                continue
            enroll_conf['enrollment']['elements'].append({elem: {'value': param[elem]}})
        print(enroll_conf)
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(enroll_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp

def clean_log_file():
    try:
        client_file = open(LOG_FILE_PATH, 'w')
        client_file.close()
    except IOError as exception:
        raise

def override_wazuh_conf(configuration):
    # Configuration for testing
    temp = get_temp_yaml(configuration)
    conf = load_wazuh_configurations(temp, __name__, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)

    clean_log_file()
    clean_password_file()
    if configuration.get('password'):
        parser = AgentAuthParser()
        parser.add_password(password=configuration['password']['value'], isFile=True,
                            path=configuration.get('authorization_pass_path'))


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
    if 'wazuh-agentd' in CURRENT_TEST_CASE.get("skips", []):
        pytest.skip("This test does not apply to agentd")
    if 'yes' in CURRENT_TEST_CASE.get("debug", []):
        print("DEBUG")

    control_service('stop', daemon='wazuh-agentd')
    clear_last_message()
    configuration = CURRENT_TEST_CASE.get('configuration', {})
    parse_configuration_string(configuration)
    override_wazuh_conf(configuration)

    if 'expected_error' in CURRENT_TEST_CASE:
        try:
            control_service('start', daemon='wazuh-agentd')
        except:
            pass
        def wait_key_changes(line):
            if CURRENT_TEST_CASE.get('expected_error') in line:
                return line
            return None
        try:
            log_monitor = FileMonitor(LOG_FILE_PATH)
            log_monitor.start(timeout=120, callback=wait_key_changes)
        except TimeoutError as err:
            assert False, f'Expected error log doesn´t occurred'
    else:
        control_service('start', daemon='wazuh-agentd')
        result = get_last_message()
        assert result != None, "Enrollment request message never arraived"
        assert result == CURRENT_TEST_CASE['message']['expected'].format(**DEFAULT_VALUES),  \
               'Expected enrollment request message does not match'

    return
