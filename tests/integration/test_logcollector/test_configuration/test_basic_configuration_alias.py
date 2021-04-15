# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.logcollector as logcollector
import wazuh_testing.api as api


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

local_internal_options = {
    'logcollector.remote_commands': 1
}

wazuh_component = get_service()

if wazuh_component == 'wazuh-manager':
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
else:
    prefix = AGENT_DETECTOR_PREFIX


if sys.platform == 'win32':
    command = 'tasklist'
else:
    command = 'ps -aux'


parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'ALIAS': 'alias'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'ALIAS': 'alias2'}
]

metadata = [
    {'log_format': 'command', 'command': f'{command}', 'alias': 'alias'},
    {'log_format': 'full_command', 'command': f'{command}', 'alias': 'alias2'}
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['COMMAND'], x['ALIAS']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def test_configuration_alias(get_local_internal_options, configure_local_internal_options,
                             get_configuration, configure_environment, restart_logcollector):
    """
    """

    cfg = get_configuration['metadata']

    log_callback = logcollector.callback_command_alias_output(cfg['alias'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([cfg], 'localfile')
