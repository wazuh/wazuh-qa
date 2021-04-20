# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
from wazuh_testing.tools import get_service



# Marks
if sys.platform != 'win32':
    pytestmark = [pytest.mark.skip, pytest.mark.tier(level=0)]
else:
    pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

wazuh_component = get_service()
prefix = AGENT_DETECTOR_PREFIX


parameters = [
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'yes'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'noTesting'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': '1234'}

]

metadata = [
    {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'yes', 'valid_value': True},
    {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'valid_value': True},
    {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'yesTesting', 'valid_value': False},
    {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'noTesting', 'valid_value': False},
    {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'testingvalue', 'valid_value': False},
    {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': '1234', 'valid_value': False}

]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['ONLY_FUTURE_EVENTS']}" for x in parameters]


def check_only_future_events_valid(cfg):
    """Check if the Wazuh run correctly with the specified only future events field.

    Ensure logcollector allows the specified future events attribute.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """
    log_callback = logcollector.callback_eventchannel_analyzing(cfg['location'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)

def check_only_future_events_invalid(cfg):
    """Check if the Wazuh fails because a invalid only future events configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callbacks are not generated.
    """
    log_callback = gc.callback_invalid_value('only-future-events', cfg['only-future-events'],
                                             prefix, severity="WARNING")
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=gc.GENERIC_CALLBACK_ERROR_MESSAGE)

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_only_future_events(get_configuration, configure_environment, restart_logcollector):
    """Check if the Wazuh only future events field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid
    only future events values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_only_future_events_valid(cfg)
    else:
        check_only_future_events_invalid(cfg)


