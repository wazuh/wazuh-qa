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
import ssl
import yaml
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.services import control_service
from conftest import *

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

configurations = load_wazuh_configurations(configurations_path, __name__)

# Fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agentd_enrollment(set_test_case, configure_socket_listener, configure_environment, create_certificates,
                           set_keys, set_pass, test_case: list):
    """
        test_logic:
            "Check that different configuration generates the adequate enrollment message or the corresponding
            error log. The configuration, keys and password files will be written with the different scenarios described
            in the test cases. After this, Agentd is started to wait for the expected result."
        checks:
            - The enrollment messages is sent when the configuration is valid
            - The enrollment message is generated as expected when the configuration is valid.
            - The error log is generated as expected when the configuration is invalid.
    """

    if 'wazuh-agentd' in test_case.get("skips", []):
        pytest.skip("This test does not apply to agentd")

    control_service('stop', daemon='wazuh-agentd')
    override_wazuh_conf(test_case.get('configuration', {}), __name__)

    if 'expected_error' in test_case:
        clean_log_file()
        try:
            control_service('start', daemon='wazuh-agentd')
        except Exception:
            pass
        try:
            log_monitor = FileMonitor(LOG_FILE_PATH)
            log_monitor.start(timeout=120, callback=lambda x: wait_until(x, test_case.get('expected_error')))
        except TimeoutError as err:
            assert False, f'Expected error log doesn´t occurred'

    else:
        clear_last_message()
        control_service('start', daemon='wazuh-agentd')
        result = get_last_message()
        assert result is not None, "Enrollment request message never arraived"
        assert result == test_case['message']['expected'].format(**DEFAULT_VALUES),  \
            'Expected enrollment request message does not match'

    return
