# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.logcollector as logcollector


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

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

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['AGE']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_age_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = logcollector.callback_analyzing_file(cfg['location'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    if sys.platform != 'win32':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.compare_config_api_response([real_configuration], 'localfile')


@pytest.mark.skipif(sys.platform == 'win32',
                    reason="Windows system currently does not support this test required")
def test_configuration_age_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = gc.callback_invalid_conf_for_localfile('age', prefix, 'ERROR')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', prefix,
                                                      conf_path=f'{wazuh_configuration}')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', prefix,
                                                      conf_path=f'{wazuh_configuration}')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")


