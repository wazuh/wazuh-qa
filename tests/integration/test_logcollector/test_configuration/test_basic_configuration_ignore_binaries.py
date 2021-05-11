# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.generic_callbacks as gc
from wazuh_testing.tools import get_service, LOG_FILE_PATH
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.services import get_process_cmd, check_if_process_is_running, control_service
from wazuh_testing.tools.file import truncate_file
import wazuh_testing.api as api
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX, FileMonitor

import subprocess as sb

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
force_restart_after_restoring = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

if sys.platform == 'win32':
    location = r'C:\testing\files*'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
    location = '/tmp/testing/files*'
    wazuh_configuration = 'etc/ossec.conf'


wazuh_component = get_service()


parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'yes'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'no'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'yesTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'noTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'testingvalue'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': '1234'}

]

metadata = [
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'yes', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'no', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'yesTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'noTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'testingvalue', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': '1234', 'valid_value': False}

]


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['IGNORE_BINARIES']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def check_ignore_binaries_valid(cfg):
    """Check if the Wazuh runs correctly with the specified ignore_binaries field value.

    Ensure logcollector allows the specified ignore_binaries attribute. Also, in the case of the manager instance,
    check if the API answer for localfile block coincides.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: In the case of Windows system, the callback for an invalid location pattern is not generated.
        AssertError: In the case of a server instance, the API response is different than the real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if sys.platform == 'win32':
        log_callback = logcollector.callback_invalid_location_pattern(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_INVALID_LOCATION)

    if wazuh_component == 'wazuh-manager':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')
    else:
        if sys.platform == 'win32':
            assert get_process_cmd('wazuh-agent.exe') != 'None'
        else:
            assert check_if_process_is_running('wazuh-logcollector')


def check_ignore_binaries_invalid(cfg):
    """Check if the Wazuh fails using a invalid ignore_binaries configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callbacks are not generated.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    log_callback = gc.callback_invalid_value('ignore_binaries', cfg['ignore_binaries'], prefix)
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


def test_ignore_binaries(get_configuration, configure_environment):
    """Check if the Wazuh ignore_binaries field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid ignore_binaries values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']
    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if cfg['valid_value']:
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_ignore_binaries_valid(cfg)
    else:
        if sys.platform == 'win32':
            expected_exception = ValueError
        else:
            expected_exception = sb.CalledProcessError

        with pytest.raises(expected_exception):
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_ignore_binaries_invalid(cfg)
