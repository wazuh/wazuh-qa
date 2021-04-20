# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.logcollector as logcollector
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.api as api
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
from wazuh_testing.tools import get_service



# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

local_internal_options = {
    'logcollector.remote_commands': '1'
}

if sys.platform == 'win32':
    location = r'C:\testing.txt'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/test.txt'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX


wazuh_component = get_service()



parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'snort-full', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'mysql_log', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'postgresql_log', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapg', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'iis', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'command', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'full_command', 'COMMAND': 'example-command'},
    {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog', 'COMMAND': 'example-command'},
    {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog', 'COMMAND': 'example-command'},
    {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'multi-line:3', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'squid', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'invalid', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'squiddasfsafas', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'iisTesting', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapgFSKF', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'jsonLGK', 'COMMAND': 'example-command'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'commandFLKD', 'COMMAND': 'example-command'}
]

metadata = [
    {'location': f'{location}', 'log_format': 'syslog', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'json', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'snort-full', 'command': 'example-command', 'valid_value': True},

    {'location': f'{location}', 'log_format': 'mysql_log', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'postgresql_log', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'nmapg', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'iis', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'command', 'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'full_command', 'command': 'example-command', 'valid_value': True},
    {'location': '/var/log/testing/current', 'log_format': 'djb-multilog',
     'command': 'example-command', 'valid_value': True},
    {'location': '/var/log/testing/current', 'log_format': 'djb-multilog',
     'command': 'example-command', 'valid_value': True},
    {'location': '/var/log/testing/current', 'log_format': 'djb-multilog',
     'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'multi-line:3',
     'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'squid',
     'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'audit',
     'command': 'example-command', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'invalid',
     'command': 'example-command', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'squiddasfsafas', 'command': 'example-command', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'iisTesting', 'command': 'example-command', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'nmapgFSKF', 'command': 'example-command', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'jsonLGK', 'command': 'example-command', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'commandFLKD', 'command': 'example-command', 'valid_value': False}
]

if sys.platform == 'win32':
    parameters.append({'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog', 'COMMAND': 'example-command'})
    parameters.append({'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'eventchannel', 'COMMAND': 'example-command'})
    metadata.append({'location': 'Security', 'log_format': 'eventlog', 'command': 'example-command', 'valid_value': True})
    metadata.append({'location': '/tmp/test.txt', 'log_format': 'eventchannel', 'command': 'example-command', 'valid_value': True})


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['COMMAND']}" for x in parameters]

log_format_not_print_analyzing_info = ['command', 'full_command', 'eventlog', 'eventchannel']

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
    """Check if the Wazuh run correctly with the specified log formats.

    Ensure logcollector allow the specified log formats. Also, in case of manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In case of a server instance, the API response is different that the real configuration.
    """
    if cfg['log_format'] not in log_format_not_print_analyzing_info :

        log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")
    elif 'command' in cfg['log_format']:

        log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    elif cfg['log_format'] == 'djb-multilog':

        log_callback = logcollector.callback_monitoring_djb_multilog(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    if wazuh_component == 'wazuh-manager':
        real_configuration = cfg.copy()
        real_configuration.pop('valid_value')
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_log_format_invalid(cfg):
    """Check if the Wazuh fails because a invalid frequency configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If error callback are not generated.
    """

    if cfg['valid_value']:
        pytest.skip('Valid values provided')

    log_callback = gc.callback_invalid_value('log_format', cfg['log_format'], prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', prefix,
                                                      conf_path=f'{wazuh_configuration}')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    if sys.platform != 'win32':
        log_callback = gc.callback_error_in_configuration('CRITICAL', prefix,
                                                          conf_path=f'{wazuh_configuration}')
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")


def test_log_format(get_configuration, configure_environment, restart_logcollector):
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_log_format_valid(cfg)
    else:
        check_log_format_invalid(cfg)
