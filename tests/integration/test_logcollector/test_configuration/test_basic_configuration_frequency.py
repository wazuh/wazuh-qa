# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import wazuh_testing.api as api
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX, FileMonitor
import wazuh_testing.generic_callbacks as gc
from wazuh_testing.tools import get_service, LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service

import subprocess as sb


LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
force_restart_after_restoring = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

local_internal_options = {'logcollector.remote_commands': '1'}

wazuh_component = get_service()


if sys.platform == 'win32':
    command = 'tasklist'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    command = 'ps -aux'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
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
    """Check if the Wazuh module runs correctly and that analyze the desired file.

    Ensure logcollector is running with the specified configuration, analyzing the designated file and,
    in the case of the Wazuh server, check if the API answer for localfile configuration block coincides
    the selected configuration.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different than the real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    real_configuration = cfg.copy()
    real_configuration.pop('valid_value')
    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_configuration_frequency_invalid(cfg):
    """Check if the Wazuh fails because an invalid frequency configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callbacks are not generated.
    """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if cfg['frequency'] in problematic_values:
        pytest.xfail("Logcolector accepts invalid values. Issue: https://github.com/wazuh/wazuh/issues/8158")

    log_callback = gc.callback_invalid_value('frequency', cfg['frequency'], prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=gc.GENERIC_CALLBACK_ERROR_MESSAGE)

    log_callback = gc.callback_error_in_configuration('ERROR', prefix,
                                                      conf_path=f'{wazuh_configuration}')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=gc.GENERIC_CALLBACK_ERROR_MESSAGE)

    if sys.platform != 'win32':

        log_callback = gc.callback_error_in_configuration('CRITICAL', prefix,
                                                          conf_path=f'{wazuh_configuration}')
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=gc.GENERIC_CALLBACK_ERROR_MESSAGE)


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
                                 get_configuration, configure_environment):
    """Check if the Wazuh frequency field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid frequency values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if cfg['valid_value']:
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_configuration_frequency_valid(cfg)
    else:
        if sys.platform == 'win32':
            expected_exception = ValueError
        else:
            expected_exception = sb.CalledProcessError

        with pytest.raises(expected_exception):
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_configuration_frequency_invalid(cfg)
