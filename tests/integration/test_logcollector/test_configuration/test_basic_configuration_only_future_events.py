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
from tempfile import gettempdir
from wazuh_testing.tools.utils import lower_case_key_dictionary_array

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"
prefix = LOG_COLLECTOR_DETECTOR_PREFIX

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

wazuh_component = get_service()

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

temp_file_path = os.path.join(gettempdir(), 'testing.log')


log_format_list = ['syslog', 'json', 'snort-full', 'mysql_log', 'postgresql_log', 'nmapg', 'iis', 'djb-multilog',
                   'multi-line:3', 'squid', 'audit']
tcases = []


if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
    log_format_list += ['eventchannel']
elif sys.platform == 'darwin':
    log_format_list += ['macos']

for log_format in log_format_list:
    if log_format == 'djb-multilog':
        location = '/var/log/testing/current'
    elif log_format == 'eventchannel':
        location = 'Security'
    elif log_format == 'macos':
        location = log_format
    else:
        location = temp_file_path

    tcases += [
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no',
            'MAX-SIZE': '9999999999999999999999999999999B', 'INVALID_VALUE': 'max-size'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '5000B',
         'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '500KB',
         'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '50MB',
         'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '5GB',
         'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no',
         'MAX-SIZE': '43423423423', 'INVALID_VALUE': 'max-size'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '-12345',
         'INVALID_VALUE': 'max-size'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': 'test',
         'INVALID_VALUE': 'max-size'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '{/}',
         'INVALID_VALUE': 'max-size'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'MAX-SIZE': '!32817--',
         'INVALID_VALUE': 'max-size'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'yes', 'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'yesTesting',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'noTesting',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'testingvalue',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': '1234',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'yes', 'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'no', 'INVALID_VALUE': ''},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'yesTesting',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'noTesting',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': 'testingvalue',
         'INVALID_VALUE': 'only-future-events'},
        {'LOCATION': f"{location}", 'LOG_FORMAT': f'{log_format}', 'ONLY-FUTURE-EVENTS': '1234',
         'INVALID_VALUE': 'only-future-events'}
    ]

metadata = lower_case_key_dictionary_array(tcases)

for element in tcases:
    element.pop('INVALID_VALUE')

parameters = tcases

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['log_format']}_{x['only-future-events']}_{x['max-size']}" + f"" if 'max-size' in x
                     else f"{x['log_format']}_{x['only-future-events']}" for x in metadata]


def check_only_future_events_valid(cfg):
    """Check if Wazuh runs correctly with the specified only future events field.

    Ensure logcollector allows the specified future events attribute.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """
    error_message = logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE

    if sys.platform == 'win32' and cfg['log_format'] == 'eventchannel':
        error_message = logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL
        log_callback = logcollector.callback_eventchannel_analyzing(cfg['location'])

    elif sys.platform == 'darwin' and cfg['log_format'] == 'macos':
        error_message = logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_MACOS
        if cfg['only-future-events'] == 'no':
            log_callback = logcollector.callback_monitoring_macos_logs(True)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_MACOS)

        log_callback = logcollector.callback_monitoring_macos_logs()

    else:
        log_callback = logcollector.callback_analyzing_file(cfg['location'])

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=error_message)


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
