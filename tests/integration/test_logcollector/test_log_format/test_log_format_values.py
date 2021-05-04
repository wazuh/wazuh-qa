# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import subprocess as sb
import wazuh_testing.logcollector as logcollector
import wazuh_testing.generic_callbacks as gc
from os import remove, path
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX, FileMonitor
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
force_restart_after_restoring = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

local_internal_options = {'logcollector.remote_commands': '1', 'logcollector.debug': '2'}

if sys.platform == 'win32':
    location = r'C:\testing.txt'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/test.txt'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'snort-full'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'squid'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'mysql_log'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'postgresql_log'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapg'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'command'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'full_command'},
    # {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog'},
    # {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog'},
    # {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog'},
    # {'LOCATION': f'{location}', 'LOG_FORMAT': 'multi-line:3'},
]

metadata = [
    {'location': f'{location}', 'log_format': 'json', 'valid_value': False},

    # {'location': f'{location}', 'log_format': 'syslog', 'valid_value': True},

    # {'location': f'{location}', 'log_format': 'snort-full', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'squid', 'command': 'example-command', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'audit', 'command': 'example-command', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'mysql_log', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'postgresql_log', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'nmapg', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'command', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'full_command', 'valid_value': True},
    # {'location': '/var/log/testing/current', 'log_format': 'djb-multilog', 'command': 'example-command', 'valid_value': True},
    # {'location': '/var/log/testing/current', 'log_format': 'djb-multilog', 'command': 'example-command', 'valid_value': True},
    # {'location': '/var/log/testing/current', 'log_format': 'djb-multilog', 'command': 'example-command', 'valid_value': True},
    # {'location': f'{location}', 'log_format': 'multi-line:3', 'command': 'example-command', 'valid_value': True},
]

if sys.platform == 'win32':
    parameters.append({'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog'})
    parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': 'eventchannel'})
    parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': 'iis'})

    metadata.append({'location': 'Security', 'log_format': 'eventlog', 'command': 'example-command', 'valid_value': True})
    metadata.append({'location': f'{location}', 'log_format': 'eventchannel', 'command': 'example-command', 'valid_value': True})
    metadata.append({'location': f'{location}', 'log_format': 'iis', 'valid_value': True}),

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

configuration_ids = [f"{x['LOG_FORMAT']}" for x in parameters]

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

def create_file(file):
    """Create an empty file."""
    with open(file, 'a') as f:
        f.write("")

def remove_file(file):
    """ Remove a file created to testing."""
    if path.exists(file):
        remove(file)

def modify_json_file(file, type):
    """Create a json content with an specific values"""
    if type:
        data = """{"issue":22,"severity":1}\n"""
    else:
        data = """{"issue:22,"severity":1}\n"""
    with open(file, 'a') as f:
        f.write(data)

def modify_syslog_file(file, type):
    """Create a syslog content with an specific values"""
    if type:
        data = """{"issue":22,"severity":1}\n"""
    else:
        data = """{"issue:22,"severity":1}\n"""
    with open(file, 'a') as f:
        f.write(data)


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
        log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)

    elif 'command' in cfg['log_format']:
        log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)
    elif cfg['log_format'] == 'djb-multilog':
        log_callback = logcollector.callback_monitoring_djb_multilog(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="The expected multilog djb log has not been produced")


def check_log_format_value_valid(conf):
    """
    Check if Wazuh runs correctly with the correct log format and content.

    Ensure logcollector allows the specified log formats.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # CHECK ONLY JSON FILE FOR NOW

    if conf['log_format'] not in log_format_not_print_analyzing_info:
        file1 = open(location, 'r')
        lines = file1.readlines()

        # Strips the newline character
        for line in lines:
            log_callback = logcollector.callback_reading_file(line.strip(), prefix=prefix)
            wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)

    #NEED TO ADD OTHER CASES



def check_log_format_value_invalid(conf):
    """
    Check if Wazuh fails because of an invalid log format or content.

       Args:
           cfg (dict): Dictionary with the localfile configuration.

       Raises:
           TimeoutError: If error callback are not generated.
   """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # CHECK ONLY JSON FILE FOR NOW

    if conf['log_format'] not in log_format_not_print_analyzing_info:
        with open(location, "r") as f:
            line = f.readline()

            log_callback = gc.callback_invalid_format_value(line, conf['log_format'], location, prefix)
            wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=gc.GENERIC_CALLBACK_ERROR_MESSAGE)


def test_log_format(get_configuration, configure_environment):
    """
    Check if Wazuh log format field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid content file and works properly in case of valid log format values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """

    conf = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if conf['valid_value']:
        create_file(location)
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_log_format_valid(conf)
        modify_json_file(location, conf['valid_value'])
        check_log_format_value_valid(conf)

    else:
        if sys.platform == 'win32':
            expected_exception = ValueError
        else:
            expected_exception = sb.CalledProcessError

        with pytest.raises(expected_exception):
            create_file(location)
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_valid(conf)
            modify_json_file(location, conf['valid_value'])
            check_log_format_value_invalid(conf)


#   remove_file(location)