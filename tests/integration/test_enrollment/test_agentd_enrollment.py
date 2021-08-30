# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import ssl
import yaml
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.services import control_service
from conftest import *

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))
configurations = load_wazuh_configurations(configurations_path, __name__)

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

socket_listener = ManInTheMiddle(address=(DEFAULT_VALUES['manager_address'], DEFAULT_VALUES['port']), family='AF_INET',
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
def test_agentd_enrollment(set_test_case, configure_socket_listener, configure_environment, set_keys):
    if 'wazuh-agentd' in CURRENT_TEST_CASE.get("skips", []):
        pytest.skip("This test does not apply to agentd")

    control_service('stop', daemon='wazuh-agentd')
    override_wazuh_conf(CURRENT_TEST_CASE.get('configuration', {}), __name__)

    if 'expected_error' in CURRENT_TEST_CASE:
        clean_log_file()
        try:
            control_service('start', daemon='wazuh-agentd')
        except:
            pass
        try:
            log_monitor = FileMonitor(LOG_FILE_PATH)
            log_monitor.start(timeout=120, callback=lambda x: wait_until(x, CURRENT_TEST_CASE.get('expected_error')))
        except TimeoutError as err:
            assert False, f'Expected error log doesn´t occurred'

    else:
        clear_last_message()
        control_service('start', daemon='wazuh-agentd')
        result = get_last_message()
        assert result != None, "Enrollment request message never arraived"
        assert result == CURRENT_TEST_CASE['message']['expected'].format(**DEFAULT_VALUES),  \
               'Expected enrollment request message does not match'

    return
