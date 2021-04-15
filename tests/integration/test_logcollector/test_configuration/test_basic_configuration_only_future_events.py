# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.api as api
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
from wazuh_testing.tools import get_service



# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

if sys.platform == 'win32':
    location = r'C:\testing.txt'
else:
    location = '/tmp/test.txt'


wazuh_component = get_service()

if wazuh_component == 'wazuh-manager':
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
else:
    prefix = AGENT_DETECTOR_PREFIX


parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yes'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'no'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'noTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': '1234'}

]

metadata = [
    {'location': f'{location}', 'log_format': 'syslog', 'only-future-events': 'yes', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'only-future-events': 'no', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'only-future-events': 'yesTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'only-future-events': 'noTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'only-future-events': 'testingvalue', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'only-future-events': '1234', 'valid_value': False}

]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['ONLY_FUTURE_EVENTS']}" for x in parameters]


def check_only_future_events_valid(cfg):
    """
    """
    log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    if wazuh_component == 'wazuh-manager':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_only_future_events_invalid(cfg):
    """
    """
    log_callback = gc.callback_invalid_value('only-future-events', cfg['only-future-events'],
                                             prefix, severity="WARNING")
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_only_future_events(get_configuration, configure_environment, restart_logcollector):
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_only_future_events_valid(cfg)
    else:
        check_only_future_events_invalid(cfg)


