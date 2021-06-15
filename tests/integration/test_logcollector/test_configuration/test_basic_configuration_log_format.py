# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess as sb
import sys

import pytest
import wazuh_testing.api as api
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.utils import lower_case_key_dictionary_array

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

default_log_format_configuration = 'wazuh_basic_configuration.yaml'
multiple_logcollector_configuration = 'wazuh_duplicated_macos_configuration.yaml'
no_location_defined_configuration = 'wazuh_no_defined_location_macos_configuration.yaml'

configurations_path_default = os.path.join(test_data_path, default_log_format_configuration)
configurations_path_multiple_logcollector = os.path.join(test_data_path, multiple_logcollector_configuration)
configurations_path_no_location = os.path.join(test_data_path, no_location_defined_configuration)

local_internal_options = {'logcollector.remote_commands': '1'}

if sys.platform == 'win32':
    no_restart_windows_after_configuration_set = True
    force_restart_after_restoring = True
    location = r'C:\testing.txt'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/test.txt'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

wazuh_component = get_service()

tcases = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'snort-full', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'mysql_log', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'postgresql_log', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapg', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'iis', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'command', 'COMMAND': 'example-command', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'full_command', 'COMMAND': 'example-command', 'VALID_VALUE': True},
    {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'multi-line:3', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'squid', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit', 'VALID_VALUE': True},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'invalid', 'VALID_VALUE': False},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'testing', 'VALID_VALUE': False},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'iisTesting', 'VALID_VALUE': False},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapgFSKF', 'VALID_VALUE': False},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'jsonLGK', 'COMMAND': 'example-command', 'VALID_VALUE': False},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'commandFLKD', 'COMMAND': 'example-command', 'VALID_VALUE': False}
]

windows_tcases = [
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog', 'VALID_VALUE': True},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'eventchannel', 'VALID_VALUE': True}
]

macos_tcases = [{'LOCATION': 'macos', 'LOG_FORMAT': 'macos', 'VALID_VALUE': True},
                {'LOCATION': '/tmp/log.txt', 'LOG_FORMAT': 'macos', 'VALID_VALUE': False},
                {'LOCATION1': 'macos', 'LOG_FORMAT1': 'macos', 'LOCATION2': 'macos', 'LOG_FORMAT2': 'macos',
                 'VALID_VALUE': False, 'CONFIGURATION': 'wazuh_duplicated_macos_configuration.yaml'},
                {'LOG_FORMAT': 'macos', 'VALID_VALUE': True,
                 'CONFIGURATION': 'wazuh_no_defined_location_macos_configuration.yaml'}
                ]

if sys.platform == 'win32':
    tcases += windows_tcases
elif sys.platform == 'darwin':
    tcases += macos_tcases

metadata = lower_case_key_dictionary_array(tcases)

for element in tcases:
    element.pop('VALID_VALUE')

parameters = tcases

parameters_default_configuration = [parameter for parameter in parameters if 'CONFIGURATION' not in parameter]
metadata_default_configuration = [metadata_value for metadata_value in metadata if
                                  'configuration' not in metadata_value]

configurations = load_wazuh_configurations(configurations_path_default, __name__,
                                           params=parameters_default_configuration,
                                           metadata=metadata_default_configuration)

configuration_ids = [f"{x['location']}_{x['log_format']}_{x['command']}" + f"" if 'command' in x
                     else f"{x['location']}_{x['log_format']}" for x in metadata_default_configuration]

parameters_multiple_logcollector_configuration = [parameter for parameter in parameters if
                                                  'CONFIGURATION' in parameter and parameter[
                                                      'CONFIGURATION'] == multiple_logcollector_configuration]
metadata_multiple_logcollector_configuration = [metadata_value for metadata_value in metadata if
                                                'configuration' in metadata_value and
                                                metadata_value['configuration'] == multiple_logcollector_configuration]

configuration_ids += [f"{x['location1']}_{x['log_format1']}_{x['location1']}_{x['log_format2']}" for x in metadata_multiple_logcollector_configuration]

configurations += load_wazuh_configurations(configurations_path_multiple_logcollector, __name__,
                                            params=parameters_multiple_logcollector_configuration,
                                            metadata=metadata_multiple_logcollector_configuration)

parameters_no_location_defined_configuration = [parameter for parameter in parameters if
                                                'CONFIGURATION' in parameter and parameter[
                                                    'CONFIGURATION'] == no_location_defined_configuration]

metadata_no_location_defined_configuration = [metadata_value for metadata_value in metadata if
                                              'configuration' in metadata_value and
                                              metadata_value['configuration'] == no_location_defined_configuration]

configurations += load_wazuh_configurations(configurations_path_no_location, __name__,
                                            params=parameters_no_location_defined_configuration,
                                            metadata=metadata_no_location_defined_configuration)

configuration_ids += [f"{x['log_format']}" for x in metadata_no_location_defined_configuration]

log_format_not_print_analyzing_info = ['command', 'full_command', 'eventlog', 'eventchannel', 'macos']

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def check_log_format_valid(cfg):
    """Check if Wazuh run correctly with the specified log formats.

    Ensure logcollector allows the specified log formats. Also, in the case of the manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if cfg['log_format'] not in log_format_not_print_analyzing_info:
        log_callback = logcollector.callback_analyzing_file(cfg['location'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)
    elif 'command' in cfg['log_format']:
        log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)
    elif cfg['log_format'] == 'djb-multilog':
        log_callback = logcollector.callback_monitoring_djb_multilog(cfg['location'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected multilog djb log has not been produced")

    elif cfg['log_format'] == 'macos':
        if 'location' in cfg and cfg['location'] != 'macos':
            log_callback = logcollector.callback_invalid_location_value_macos(cfg['location'])
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message="The expected warning invalid macos value has not been produced")

        log_callback = logcollector.callback_monitoring_macos_logs()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected macos log monitoring has not been produced")

    if wazuh_component == 'wazuh-manager':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_log_format_invalid(cfg):
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    """Check if Wazuh fails because a invalid frequency configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callback are not generated.
    """

    if cfg['valid_value']:
        pytest.skip('Valid values provided')

    log_callback = gc.callback_invalid_value('log_format', cfg['log_format'], prefix)
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


def test_log_format(get_local_internal_options, configure_local_internal_options, get_configuration,
                    configure_environment):
    """Check if Wazuh log format field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid values and works properly in case of valid
    log format values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if cfg['valid_value']:
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_log_format_valid(cfg)
    else:
        if sys.platform == 'win32':
            expected_exception = ValueError
        else:
            expected_exception = sb.CalledProcessError

        with pytest.raises(expected_exception):
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_invalid(cfg)
