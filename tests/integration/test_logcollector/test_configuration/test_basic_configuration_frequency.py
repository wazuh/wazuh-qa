# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import wazuh_testing.api as api
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.generic_callbacks as gc
from wazuh_testing.tools import get_service

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
    wazuh_configuration = 'ossec.conf'

else:
    command = 'ps -aux'
    wazuh_configuration = 'etc/ossec.conf'

parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': '3'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': '10'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': '100000'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': '3s'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': 'Testing'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': '3Testing'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': '3s5m'},
    {'LOG_FORMAT': 'command', 'COMMAND': f'{command}', 'FREQUENCY': 'Testing3'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': '3'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': '10'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': '100000'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': '3s'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': 'Testing'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': '3Testing'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': '3s5m'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'{command}', 'FREQUENCY': 'Testing3'},

]

metadata = [
    {'log_format': 'command', 'command': f'{command}', 'frequency': '3', 'valid_value': True},
    {'log_format': 'command', 'command': f'{command}', 'frequency': '10', 'valid_value': True},
    {'log_format': 'command', 'command': f'{command}', 'frequency': '100000', 'valid_value': True},
    {'log_format': 'command', 'command': f'{command}', 'frequency': '3s', 'valid_value': False},
    {'log_format': 'command', 'command': f'{command}', 'frequency': 'Testing', 'valid_value': False},
    {'log_format': 'command', 'command': f'{command}', 'frequency': '3Testing', 'valid_value': False},
    {'log_format': 'command', 'command': f'{command}', 'frequency': '3s5m', 'valid_value': False},
    {'log_format': 'command', 'command': f'{command}', 'frequency': 'Testing3', 'valid_value': False},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': '3', 'valid_value': True},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': '10', 'valid_value': True},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': '100000', 'valid_value': True},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': '3s', 'valid_value': False},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': 'Testing', 'valid_value': False},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': '3Testing', 'valid_value': False},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': '3s5m', 'valid_value': False},
    {'log_format': 'full_command', 'command': f'{command}', 'frequency': 'Testing3', 'valid_value': False},
]

problematic_values = ['3s', '3s5m', '3Testing']

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['COMMAND'], x['FREQUENCY']}" for x in parameters]


def check_configuration_frequency_valid(cfg):
    """
    """

    log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    real_configuration = cfg.copy()
    real_configuration.pop('valid_value')
    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_configuration_frequency_invalid(cfg):
    """
    """
    if cfg['frequency'] in problematic_values:
        pytest.xfail("Logcolector accepts invalid values. Issue: https://github.com/wazuh/wazuh/issues/8158")

    log_callback = gc.callback_invalid_value('frequency', cfg['frequency'], prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', prefix,
                                                      conf_path=f'{wazuh_configuration}')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    if sys.platform != 'win32':

        log_callback = gc.callback_error_in_configuration('CRITICAL', prefix,
                                                          conf_path=f'{wazuh_configuration}')
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def test_configuration_frequency(get_local_internal_options, configure_local_internal_options,
                                 get_configuration, configure_environment, restart_logcollector):
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_configuration_frequency_valid(cfg)
    else:
        check_configuration_frequency_invalid(cfg)
