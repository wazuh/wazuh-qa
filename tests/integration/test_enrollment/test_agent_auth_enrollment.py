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

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import load_tests, truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback
from conftest import *

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

configurations = load_wazuh_configurations(configurations_path, __name__)
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))
AGENT_AUTH_TIMEOUT = 5

# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_auth_enrollment(set_test_case, configure_socket_listener, configure_environment, create_certificates,
                               set_keys, set_pass, test_case: list):
    """
        test_logic:
            "Check that different configuration generates the adequate enrollment message or the corresponding
            error log. Agent-auth will be executed using the different parameters and with different keys and password
            files scenarios as described in the test cases."
        checks:
            - The enrollment messages is sent when the configuration is valid
            - The enrollment message is generated as expected when the configuration is valid.
            - The error log is generated as expected when the configuration is invalid.
    """
    if 'agent-auth' in test_case.get('skips', []):
        pytest.skip('This test does not apply to agent-auth')

    control_service('stop', daemon='wazuh-agentd')

    if 'expected_error' in test_case:
        truncate_file(LOG_FILE_PATH)
        log_monitor = FileMonitor(LOG_FILE_PATH)
        launch_agent_auth(test_case.get('configuration', {}))

        if test_case.get('expected_fail'):
            with pytest.raises(TimeoutError):
                log_monitor.start(timeout=AGENT_AUTH_TIMEOUT,
                                  callback=make_callback(test_case.get('expected_error'), prefix='.*', escape=True))
        else:
            log_monitor.start(timeout=AGENT_AUTH_TIMEOUT,
                            callback=make_callback(test_case.get('expected_error'), prefix='.*', escape=True),
                            error_message='Expected error log does not occured')

    else:
        clear_last_message()
        launch_agent_auth(test_case.get('configuration', {}))
        result = get_last_message(AGENT_AUTH_TIMEOUT)
        assert result is not None, 'Enrollment request message never arrived'
        assert result == test_case['message']['expected'].format(**DEFAULT_VALUES), \
            'Expected enrollment request message does not match'
