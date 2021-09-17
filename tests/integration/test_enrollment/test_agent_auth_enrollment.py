'''
brief: This module verifies the correct behavior of the agent-auth enrollment tool under different configurations
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
metadata:
    component:
        - Agent
    modules:
        - agent-auth
    daemons:
        - agent-auth
    operating_system:
        - Ubuntu
        - CentOS
        - Windows
    tiers:
        - 0
    tags:
        - Enrollment
        - Agent-auth
'''

import pytest
import os

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.monitoring import QueueMonitor, make_callback
from wazuh_testing.tools.utils import get_host_name
from enrollment import AGENT_AUTH_ENROLLMENT_REQUEST_TIMEOUT, launch_agent_auth

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
tests_path = os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml')
configurations_path = os.path.join(test_data_path, 'wazuh_enrollment_conf.yaml')
tests = read_yaml(tests_path)
configurations = load_wazuh_configurations(configurations_path, __name__)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope='function', params=tests)
def get_current_test_case(request):
    """Get current test case from the module"""
    return request.param


@pytest.fixture(scope='module')
def shutdown_agentd():
    control_service('stop', daemon='wazuh-agentd')


def test_agent_auth_enrollment(configure_environment, shutdown_agentd, get_current_test_case, create_certificates,
                               set_keys, set_password, file_monitoring, configure_socket_listener, request):
    """
        test_logic:
            "Check that different configuration generates the adequate enrollment message or the corresponding
            error log. Agent-auth will be executed using the different parameters and with different keys and password
            files scenarios as described in the test cases."
        checks:
            - The enrollment message is sent when the configuration is valid
            - The enrollment message is generated as expected when the configuration is valid.
            - The error log is generated as expected when the configuration is invalid.
    """
    if 'agent-auth' in get_current_test_case.get('skips', []):
        pytest.skip('This test does not apply to agent-auth')

    launch_agent_auth(get_current_test_case.get('configuration', {}))

    if 'expected_error' in get_current_test_case:
        log_monitor = request.module.log_monitor
        try:
            log_monitor.start(timeout=AGENT_AUTH_ENROLLMENT_REQUEST_TIMEOUT,
                              callback=make_callback(get_current_test_case.get('expected_error'), prefix='.*',
                                                     escape=True),
                              error_message = 'Expected error log does not occured.')
        except Exception as error:
            if get_current_test_case.get('expected_fail'):
                reason = get_current_test_case.get('expected_fail_reason')
                pytest.xfail(f'Xfailing due to {reason}')
            else:
                raise error

    else:
        test_expected = get_current_test_case['message']['expected'].format(host_name=get_host_name()).encode()
        test_response = get_current_test_case['message']['response'].format(host_name=get_host_name()).encode()
        # Monitor MITM queue
        socket_monitor = QueueMonitor(request.module.socket_listener.queue)
        event = (test_expected, test_response)

        try:
            # Start socket monitoring
            socket_monitor.start(timeout=AGENT_AUTH_ENROLLMENT_REQUEST_TIMEOUT, callback=lambda received_event: event == received_event,
                                 error_message='Enrollment request message never arrived', update_position=False)
        finally:
            socket_monitor.stop()
