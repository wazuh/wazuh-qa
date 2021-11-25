# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.logcollector as logcollector
import wazuh_testing.api as api
from wazuh_testing.tools.utils import lower_case_key_dictionary_array


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

local_internal_options = {'logcollector.remote_commands': '1', 'logcollector.debug': '2', 'windows.debug': '2'}

wazuh_component = get_service()

if sys.platform == 'win32':
    command = 'tasklist'
    no_restart_windows_after_configuration_set = True
elif sys.platform == 'darwin':
    command = 'ps aux'
elif sys.platform == 'sunos5':
    command = 'ps aux -xww'    
else:
    command = 'ps -aux'


parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'ALIAS': 'alias'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'ALIAS': 'alias2'}
]

metadata = lower_case_key_dictionary_array(parameters)

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['log_format']}_{x['command']}_{x['alias']}" for x in metadata]


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_configuration_alias(configure_local_internal_options_module,
                             get_configuration, configure_environment, file_monitoring, restart_logcollector):
    """Check if the module runs correctly with the specified command monitoring configuration and that it uses an alias value.
    Ensure command monitoring uses specified alias value. Also, in the case of the manager instance, check if the API
    answer for localfile configuration block coincides.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
        AssertError: In the case of a server instance, the API response is different from the real configuration.
    """
    cfg = get_configuration['metadata']

    log_callback = logcollector.callback_command_alias_output(cfg['alias'])
    log_monitor.start(timeout=10, callback=log_callback,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([cfg], 'localfile')
