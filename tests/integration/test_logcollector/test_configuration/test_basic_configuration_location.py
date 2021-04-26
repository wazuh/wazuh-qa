# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
import pytest
import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import get_service
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
from wazuh_testing.tools.services import get_process_cmd, check_if_process_is_running


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')


wazuh_component = get_service()

if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX


if sys.platform == 'win32':
    parameters = [
        {'LOCATION': 'Microsoft-Windows-Sysmon/Operational', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': r'C:\Users\wazuh\myapp\*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
         'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Application', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'System', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Microsoft-Windows-Sysmon/Operational', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Microsoft-Windows-Windows Defender/Operational', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'File Replication Service', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Service Microsoft-Windows-TerminalServices-RemoteConnectionManager',
         'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': r'C:\xampp\apache\logs\*.log', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'C:\logs\file-%Y-%m-%d.log', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'C:\Testing white spaces', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'C:\FOLDER\*', 'LOG_FORMAT': 'json'},
    ]

    metadata = [
        {'location': 'Microsoft-Windows-Sysmon/Operational', 'log_format': 'eventchannel'},
        {'location': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'log_format': 'eventchannel'},
        {'location': 'Application', 'log_format': 'eventchannel'},
        {'location': 'Security', 'log_format': 'eventchannel'},
        {'location': 'System', 'log_format': 'eventchannel'},
        {'location': 'Microsoft-Windows-Sysmon/Operational', 'log_format': 'eventchannel'},
        {'location': 'Microsoft-Windows-Windows Defender/Operational', 'log_format': 'eventchannel'},
        {'location': 'File Replication Service', 'log_format': 'eventchannel'},
        {'location': 'Service Microsoft-Windows-TerminalServices-RemoteConnectionManager',
         'log_format': 'eventchannel'},
        {'location': r'C:\Users\wazuh\myapp', 'log_format': 'syslog'},
        {'location': r'C:\xampp\apache\logs\*.log', 'log_format': 'syslog'},
        {'location': r'C:\logs\file-%Y-%m-%d.log', 'log_format': 'syslog'},
        {'location': r'C:\Testing white spaces', 'log_format': 'syslog'},
        {'location': r'C:\FOLDER\*', 'log_format': 'json'},
    ]

else:
    parameters = [
        {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/Testing white spaces', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'/tmp/%F%H%K%L/*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/test.*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/c*test.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/?¿^*We.- Nmae', 'LOG_FORMAT': 'json'},
        {'LOCATION': '/tmp/testing/file.log-%Y-%m-%d', 'LOG_FORMAT': 'syslog'},
    ]

    metadata = [
        {'location': '/tmp/test.txt', 'log_format': 'syslog'},
        {'location': '/*', 'log_format': 'syslog'},
        {'location': '/Testing white spaces', 'log_format': 'syslog'},
        {'location': r'/tmp/%F%H%K%L/*', 'log_format': 'syslog'},
        {'location': '/tmp/test.*', 'log_format': 'syslog'},
        {'location': '/tmp/c*test.txt', 'log_format': 'syslog'},
        {'location': '/tmp/?¿^*We.- Nmae', 'log_format': 'json'},
        {'location': '/tmp/testing/file.log-%Y-%m-%d', 'log_format': 'syslog'},
    ]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_location(get_configuration, configure_environment, restart_logcollector):
    """Check if Wazuh runs correctly with the specified location field value.

    Ensure logcollector allows the specified locations. Also, in the case of the manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    cfg = get_configuration['metadata']

    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([cfg], 'localfile')
    else:
        if sys.platform == 'win32':
            assert get_process_cmd('wazuh-agent.exe') != 'None'
        else:
            assert check_if_process_is_running('wazuh-logcollector')
