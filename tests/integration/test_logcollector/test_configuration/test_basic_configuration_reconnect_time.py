# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import get_service
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

if sys.platform == 'win32':
    location = r'C:\testing.txt'
    wazuh_configuration = 'ossec.conf'

else:
    location = '/tmp/test.txt'
    wazuh_configuration = 'etc/ossec.conf'


wazuh_component = get_service()

if wazuh_component == 'wazuh-manager':
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
else:
    prefix = AGENT_DETECTOR_PREFIX


parameters = [
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '3s'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '4000s'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '5m'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '99h'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '94201d'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '44sTesting'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': 'Testing44s'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '9hTesting'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '400mTesting'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': '3992'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': f'{location}', 'RECONNECT_TIME': 'Testing'},
]

metadata = [
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '3s', 'valid_value': True},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '4000s', 'valid_value': True},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '5m', 'valid_value': True},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '99h', 'valid_value': True},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '94201d', 'valid_value': True},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '44sTesting', 'valid_value': False},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': 'Testing44s', 'valid_value': False},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '9hTesting', 'valid_value': False},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '400mTesting', 'valid_value': False},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': '3992', 'valid_value': False},
    {'log_format': 'syslog', 'location': f'{location}', 'reconnect_time': 'Testing', 'valid_value': False},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['LOCATION'], x['RECONNECT_TIME']}" for x in parameters]
problematic_values = ['44sTesting', '9hTesting', '400mTesting', '3992']


def check_configuration_reconnect_time_valid(cfg):
    """
    """
    if wazuh_component == 'wazuh-manager':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_configuration_reconnect_time_invalid(cfg):
    """
    """
    if cfg['reconnect_time'] in problematic_values:
        pytest.xfail("Logcolector accepts invalid values. Issue: https://github.com/wazuh/wazuh/issues/8158")

    log_callback = logcollector.callback_invalid_reconnection_time(prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_reconnect_time(get_configuration, configure_environment, restart_logcollector):
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_configuration_reconnect_time_valid(cfg)
    else:
        check_configuration_reconnect_time_invalid(cfg)

