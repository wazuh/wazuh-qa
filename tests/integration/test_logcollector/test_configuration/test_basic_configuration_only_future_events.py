# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import AGENT_DETECTOR_PREFIX, FileMonitor, LOG_COLLECTOR_DETECTOR_PREFIX
from wazuh_testing.tools import get_service, LOG_FILE_PATH

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
# pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

wazuh_component = get_service()

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
    parameters = [
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no',
            'MAX_SIZE': '9999999999999999999999999999999B'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '5000B'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '500KB'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '50MB'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '5GB'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '43423423423'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '-12345'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': 'test'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '{}'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '!32817--'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'yes'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'no'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'noTesting'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'ONLY_FUTURE_EVENTS': '1234'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yes'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'no'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'noTesting'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': '1234'}
    ]

    metadata = [
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no',
         'max-size': '9999999999999999999999999999999B', 'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '5000B',
            'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '500KB',
            'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '50MB',
            'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '5GB',
            'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '43423423423',
         'invalid_value': 'max-size'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '-12345',
         'invalid_value': 'max-size'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': 'test',
         'invalid_value': 'max-size'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '{}',
         'invalid_value': 'max-size'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'max-size': '!32817--',
         'invalid_value': 'max-size'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'yes', 'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'no', 'invalid_value': ''},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'yesTesting',
         'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'noTesting', 'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': 'testingvalue',
         'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'eventchannel', 'only-future-events': '1234', 'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'syslog', 'only-future-events': 'yes', 'invalid_value': ''},
        {'location': 'Security', 'log_format': 'syslog', 'only-future-events': 'no', 'invalid_value': ''},
        {'location': 'Security', 'log_format': 'syslog', 'only-future-events': 'yesTesting',
         'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'syslog', 'only-future-events': 'noTesting', 'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'syslog', 'only-future-events': 'testingvalue',
         'invalid_value': 'only-future-events'},
        {'location': 'Security', 'log_format': 'syslog', 'only-future-events': '1234', 'invalid_value': 'only-future-events'}
    ]

else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
    parameters = [
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no',
            'MAX_SIZE': '9999999999999999999999999999999B'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '5000B'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '500KB'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '50MB'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '5GB'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '43423423423'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '-12345'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': 'test'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '{/}'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '!32817--'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'yes'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'no'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'noTesting'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'json', 'ONLY_FUTURE_EVENTS': '1234'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yes'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'no'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'noTesting'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
        {'LOCATION': '/var/log/testing.log', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': '1234'}
    ]

    metadata = [
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': '',
            'max-size': '9999999999999999999999999999999B'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': '',
            'max-size': '5000B'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': '',
            'max-size': '500KB'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': '',
            'max-size': '50MB'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': '',
            'max-size': '5GB'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': 'max-size',
         'max-size': '43423423423'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': 'max-size',
         'max-size': '-12345'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': 'max-size',
         'max-size': 'test'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': 'max-size',
         'max-size': '{/}'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': 'max-size',
         'max-size': '!32817--'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'yes', 'invalid_value': ''},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'no', 'invalid_value': ''},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'yesTesting',
         'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'noTesting', 'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': 'testingvalue',
         'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'json', 'only-future-events': '1234', 'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'syslog', 'only-future-events': 'yes', 'invalid_value': ''},
        {'location': '/var/log/testing.log', 'log_format': 'syslog', 'only-future-events': 'no', 'invalid_value': ''},
        {'location': '/var/log/testing.log', 'log_format': 'syslog', 'only-future-events': 'yesTesting',
         'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'syslog', 'only-future-events': 'noTesting', 'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'syslog', 'only-future-events': 'testingvalue',
         'invalid_value': 'only-future-events'},
        {'location': '/var/log/testing.log', 'log_format': 'syslog', 'only-future-events': '1234', 'invalid_value': 'only-future-events'}
    ]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT']}_{x['ONLY_FUTURE_EVENTS']}_{x['MAX_SIZE']}" + f"" if 'MAX_SIZE' in x
                     else f"{x['LOG_FORMAT']}_{x['ONLY_FUTURE_EVENTS']}" for x in parameters]


def check_only_future_events_valid(cfg):
    """Check if Wazuh runs correctly with the specified only future events field.

    Ensure logcollector allows the specified future events attribute.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """
    if sys.platform == 'win32':
        log_callback = logcollector.callback_eventchannel_analyzing(cfg['location'])
    else:
        log_callback = logcollector.callback_analyzing_file(cfg['location'])

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)


def check_only_future_events_invalid(cfg):
    """Check if Wazuh fails due to a invalid only future events configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callbacks are not generated.
    """

    invalid_value = cfg['invalid_value']

    if invalid_value == 'max-size':
        option_value = cfg['max-size']
        log_callback = gc.callback_invalid_attribute('only-future-events', 'max-size', option_value,
                                                     prefix, severity="WARNING")
    else:
        option_value = cfg['only-future-events']
        log_callback = gc.callback_invalid_value(invalid_value, option_value, prefix, severity="WARNING")

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=gc.GENERIC_CALLBACK_ERROR_MESSAGE)


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_only_future_events(get_configuration, configure_environment, restart_logcollector):
    """Check if Wazuh only future events field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid
    only future events values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']

    if cfg['invalid_value'] == '':
        check_only_future_events_valid(cfg)
    else:
        check_only_future_events_invalid(cfg)
