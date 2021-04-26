# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
import sys
import wazuh_testing.api as api
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service
import subprocess as sb

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')
wazuh_component = get_service()

no_restart_windows_after_configuration_set = True
force_restart_after_restoring = True

if sys.platform == 'win32':
    location = r'C:\testing\file.txt'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/testing.txt'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '3s'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '4000s'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '5m'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '99h'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '94201d'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '44sTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': 'Testing44s'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '9hTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '400mTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '3992'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': 'Testing'},
]
metadata = [
    {'location': f'{location}', 'log_format': 'syslog', 'age': '3s', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '4000s', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '5m', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '99h', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '94201d', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '44sTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'age': 'Testing44s', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '9hTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '400mTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '3992', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'age': 'Testing', 'valid_value': False},
]

problematic_values = ['44sTesting', '9hTesting', '400mTesting', '3992']
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['AGE']}" for x in parameters]


def check_configuration_age_valid(cfg):
    """Check if the Wazuh module runs correctly and analyze the desired file.

    Ensure logcollector is running with the specified configuration, analyzing the designated file and,
    in the case of the Wazuh server, check if the API answer for localfile configuration block coincides
    the selected configuration.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different from real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)
    if wazuh_component == 'wazuh-manager':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_configuration_age_invalid(cfg):
    """Check if the Wazuh fails because the invalid age configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callback are not generated.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if cfg['age'] in problematic_values:
        pytest.xfail("Logcollector accepts invalid values. Issue: https://github.com/wazuh/wazuh/issues/8158")

    log_callback = gc.callback_invalid_conf_for_localfile('age', prefix, severity='ERROR')
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


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_age(get_configuration, configure_environment):
    """Check if the Wazuh age field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid age values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if cfg['valid_value']:
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_configuration_age_valid(cfg)
    else:
        if sys.platform == 'win32':
            expected_exception = ValueError
        else:
            expected_exception = sb.CalledProcessError

        with pytest.raises(expected_exception):
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_configuration_age_invalid(cfg)
