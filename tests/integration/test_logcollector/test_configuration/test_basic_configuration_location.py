# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
import pytest
import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import get_service
from wazuh_testing.tools.services import get_process_cmd, check_if_process_is_running
from wazuh_testing.tools.utils import lower_case_key_dictionary_array
import tempfile

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

wazuh_component = get_service()

folder_path = tempfile.gettempdir()

parameters = [
    {'LOCATION': f"{os.path.join(folder_path, 'test.txt')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': f"{os.path.join(folder_path, '*')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': f"{os.path.join(folder_path, 'Testing white spaces')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': fr"{os.path.join(folder_path, '%F%H%K%L')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': fr"{os.path.join(folder_path, 'test.*')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': fr"{os.path.join(folder_path, 'c*test.txt')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': fr"{os.path.join(folder_path, '?¿^*We.- Nmae')}", 'LOG_FORMAT': 'syslog'},
    {'LOCATION': fr"{os.path.join(folder_path, 'file.log-%Y-%m-%d')}", 'LOG_FORMAT': 'syslog'},
]

windows_parameters = [
    {'LOCATION': 'Microsoft-Windows-Sysmon/Operational', 'LOG_FORMAT': 'eventchannel'},
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
]

macos_parameters = [{'LOCATION': 'oslog', 'LOG_FORMAT': 'oslog'}]

if sys.platform == 'win32':
    parameters += windows_parameters
elif sys.platform == 'darwin':
    parameters += macos_parameters

metadata = lower_case_key_dictionary_array(parameters)

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
