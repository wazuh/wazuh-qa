'''
brief: This module verifies the correct behavior of Wazuh Agentd during the enrollment under different configurations.
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
metadata:
    component:
        - Agent
    modules:
        - Agentd
    daemons:
        - Agentd
    operating_system:
        - Ubuntu
        - CentOS
        - Windows
    tiers:
        - 0
    tags:
        - Enrollment
        - Agentd
'''

import pytest
import os
import socket
import yaml

from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import load_tests
from wazuh_testing.tools.monitoring import QueueMonitor, make_callback
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.utils import get_host_name

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_enrollment_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)
host_name = socket.gethostname()
AGENTD_TIMEOUT = 20

daemons_handler_configuration = {'function': {'daemons': ['wazuh-agentd'], 'ignore_errors': False},
                                 'module':  {'daemons': ['wazuh-modulesd', 'wazuh-analysisd'], 'ignore_errors': False},
                                 'configuration': {'daemons': ['wazuh-syscheckd'], 'ignore_errors': False}}


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope='function', params=tests)
def get_current_test_case(request):
    """Get current test case from the module"""
    return request.param


@pytest.fixture(scope='function')
def restart_agentd():
    try:
        control_service('restart', daemon='wazuh-agentd')
    except Exception:
        pass
    yield
    control_service('stop', daemon='wazuh-agentd')


def test_agentd_enrollment(configure_environment, override_wazuh_conf, get_current_test_case, create_certificates,
                           set_keys, set_pass, file_monitoring, configure_socket_listener, restart_agentd, request):
    """
        test_logic:
            "Check that different configuration generates the adequate enrollment message or the corresponding
            error log. The configuration, keys and password files will be written with the different scenarios described
            in the test cases. After this, Agentd is started to wait for the expected result."
        checks:
            - The enrollment message is sent when the configuration is valid
            - The enrollment message is generated as expected when the configuration is valid.
            - The error log is generated as expected when the configuration is invalid.
    """
    if 'wazuh-agentd' in get_current_test_case.get('skips', []):
        pytest.skip("This test does not apply to agentd")

    if 'expected_error' in get_current_test_case:
        log_monitor = request.module.log_monitor
        if get_current_test_case.get('expected_fail'):
            with pytest.raises(TimeoutError):
                log_monitor.start(timeout=AGENTD_TIMEOUT,
                                  callback=make_callback(get_current_test_case.get('expected_error'), prefix='.*',
                                                         escape=True))
        else:
            log_monitor.start(timeout=AGENTD_TIMEOUT,
                              callback=make_callback(get_current_test_case.get('expected_error'), prefix='.*',
                                                     escape=True),
                              error_message='Expected error log does not occured')

    else:
        test_expected = get_current_test_case['message']['expected'].format(host_name=get_host_name()).encode()
        test_response = get_current_test_case['message']['response'].format(host_name=get_host_name()).encode()

        # Monitor MITM queue
        socket_monitor = QueueMonitor(request.module.socket_listener.queue)
        event = (test_expected, test_response)

        try:
            # Start socket monitoring
            socket_monitor.start(timeout=AGENTD_TIMEOUT, callback=lambda received_event: event == received_event,
                                 error_message='Enrollment request message never arrived', update_position=False)
        finally:
            socket_monitor.stop()
