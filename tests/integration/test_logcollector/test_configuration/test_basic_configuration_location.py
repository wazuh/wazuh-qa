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
from wazuh_testing.logcollector import WINDOWS_CHANNEL_LIST
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

windows_parameters = []
for channel in WINDOWS_CHANNEL_LIST:
    windows_parameters.append({'LOCATION': f'{channel}', 'LOG_FORMAT': 'eventchannel'})

macos_parameters = [{'LOCATION': 'macos', 'LOG_FORMAT': 'macos'}]

if sys.platform == 'win32':
    parameters += windows_parameters
elif sys.platform == 'darwin':
    parameters += macos_parameters

metadata = lower_case_key_dictionary_array(parameters)

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['location']}_{x['log_format']}" for x in metadata]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
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
            assert check_if_process_is_running('wazuh-agent.exe') == True
        else:
            check_if_process_is_running('wazuh-logcollector')
