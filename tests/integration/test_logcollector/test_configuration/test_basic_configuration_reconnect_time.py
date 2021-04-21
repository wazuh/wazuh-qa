# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

# Marks
if sys.platform != 'win32':
    pytestmark = [pytest.mark.skip, pytest.mark.tier(level=0)]
else:
    pytestmark = pytest.mark.tier(level=0)

location = r'Security'
wazuh_configuration = 'ossec.conf'
prefix = AGENT_DETECTOR_PREFIX


parameters = [
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '3s'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '4000s'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '5m'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '99h'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '94201d'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '44sTesting'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': 'Testing44s'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '9hTesting'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '400mTesting'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': '3992'},
    {'LOG_FORMAT': 'eventchannel', 'LOCATION': f'{location}', 'RECONNECT_TIME': 'Testing'},
]

metadata = [
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '3s', 'valid_value': True},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '4000s', 'valid_value': True},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '5m', 'valid_value': True},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '99h', 'valid_value': True},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '94201d', 'valid_value': True},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '44sTesting', 'valid_value': False},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': 'Testing44s', 'valid_value': False},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '9hTesting', 'valid_value': False},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '400mTesting', 'valid_value': False},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': '3992', 'valid_value': False},
    {'log_format': 'eventchannel', 'location': f'{location}', 'reconnect_time': 'Testing', 'valid_value': False},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['LOCATION'], x['RECONNECT_TIME']}" for x in parameters]
problematic_values = ['44sTesting', '9hTesting', '400mTesting', '3992']


def check_configuration_reconnect_time_valid():
    """Check if the Wazuh module run correctly and that analyze the desired eventchannel.

    Ensure logcollector is running with the specified configuration, analyzing the designate eventchannel.


    Raises:
        TimeoutError: If the "Analyzing eventchannel" callback is not generated.
    """

    log_callback = logcollector.callback_eventchannel_analyzing('Security')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")


def check_configuration_reconnect_time_invalid(cfg):
    """Check if the Wazuh fails because a invalid reconnect time attribute configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callback are not generated.
    """
    if cfg['reconnect_time'] in problematic_values:
        pytest.xfail("Logcolector accepts invalid values. Issue: https://github.com/wazuh/wazuh/issues/8158")

    log_callback = logcollector.callback_invalid_reconnection_time(prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected invalid reconnection time error has not been produced")


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_reconnect_time(get_configuration, configure_environment, restart_logcollector):
    """Check if the Wazuh reconnect time field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid reconnect time values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_configuration_reconnect_time_valid()
    else:
        check_configuration_reconnect_time_invalid(cfg)

