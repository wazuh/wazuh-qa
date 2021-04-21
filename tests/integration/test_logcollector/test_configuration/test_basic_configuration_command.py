# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import wazuh_testing.api as api
from wazuh_testing.tools import get_service
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')
wazuh_component = get_service()


if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

local_internal_options = {
    'logcollector.remote_commands': 1
}

parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'df -P'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'find / -type f -perm 4000'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'ls /tmp/*'},
    {'LOG_FORMAT': 'command', 'COMMAND': '/tmp/script/my_script -a 1 -v 2 -b 3 -g 444 -k Testing'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'df -P'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'find / -type f -perm 4000'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'ls /tmp/*'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': '/tmp/script/my_script -a 1 -v 2 -b 3 -g 444 -k Testing'}
]
metadata = [
    {'log_format': 'command', 'command': 'echo Testing'},
    {'log_format': 'command', 'command': 'df -P'},
    {'log_format': 'command', 'command': 'find / -type f -perm 4000'},
    {'log_format': 'command', 'command': 'ls /tmp/*'},
    {'log_format': 'command', 'command': '/tmp/script/my_script -a 1 -v 2 -b 3 -g 444 -k Testing'},
    {'log_format': 'full_command', 'command': 'echo Testing'},
    {'log_format': 'full_command', 'command': 'df -P'},
    {'log_format': 'full_command', 'command': 'find / -type f -perm 4000'},
    {'log_format': 'full_command', 'command': 'ls /tmp/*'},
    {'log_format': 'full_command', 'command': '/tmp/script/my_script -a 1 -v 2 -b 3 -g 444 -k Testing'},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['COMMAND']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def test_configuration_command(get_local_internal_options, configure_local_internal_options, get_configuration,
                                     configure_environment, restart_logcollector):
    """Check if the Wazuh run correctly with the specified command monitoring configuration.

    Ensure command monitoring allow the specified attributes. Also, in the case of manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    cfg = get_configuration['metadata']

    log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([cfg], 'localfile')
