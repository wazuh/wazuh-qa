# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
from wazuh_testing.tools import monitoring
from wazuh_testing.tools import get_service
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_command_conf.yaml')
wazuh_component = get_service()

if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

local_internal_options = {
    'logcollector.remote_commands': 1,
    'logcollector.debug': 2
}

parameters = [
    # Command with empty output.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo hello world', 'ALIAS': 'goodbye'},
    # Command not found.
    {'LOG_FORMAT': 'command', 'COMMAND': 'not_found_command -o option -v', 'ALIAS': ''},
    # Command that doesn't end.
    {'LOG_FORMAT': 'command', 'COMMAND': 'tail -f /var/ossec/logs/ossec.log', 'ALIAS': ''},
    # Command with too long output.
    {'LOG_FORMAT': 'command', 'COMMAND': 'ls -R /tmp', 'ALIAS': ''},
    # Command that fails.
    {'LOG_FORMAT': 'command', 'COMMAND': 'cat doesntexists.txt', 'ALIAS': ''},
    # Commands including special characters and "foreign" language characters.
    {'LOG_FORMAT': 'command', 'COMMAND': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo ***', 'ALIAS': ''},

    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo hello world', 'ALIAS': 'goodbye'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'not_found_command -o option -v', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'tail -f /var/ossec/logs/ossec.log', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'ls -R /tmp', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'cat doesntexists.txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo ***', 'ALIAS': ''},
]
metadata = [
    {'log_format': 'command', 'command': 'echo hello world', 'alias': 'goodbye'},
    {'log_format': 'command', 'command': 'not_found_command -o option -v', 'alias': ''},
    {'log_format': 'command', 'command': 'tail -f /var/ossec/logs/ossec.log', 'alias': ''},
    {'log_format': 'command', 'command': 'ls -R /tmp', 'alias': ''},
    {'log_format': 'command', 'command': 'cat doesntexists.txt', 'alias': ''},
    {'log_format': 'command', 'command': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'alias': ''},
    {'log_format': 'command', 'command': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'alias': ''},
    {'log_format': 'command', 'command': 'echo ***', 'alias': ''},

    {'log_format': 'full_command', 'command': 'echo hello world', 'alias': 'goodbye'},
    {'log_format': 'full_command', 'command': 'not_found_command -o option -v', 'alias': ''},
    {'log_format': 'full_command', 'command': 'tail -f /var/ossec/logs/ossec.log', 'alias': ''},
    {'log_format': 'full_command', 'command': 'ls -R /tmp', 'alias': ''},
    {'log_format': 'full_command', 'command': 'cat doesntexists.txt', 'alias': ''},
    {'log_format': 'full_command', 'command': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'alias': ''},
    {'log_format': 'full_command', 'command': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'alias': ''},
    {'log_format': 'full_command', 'command': 'echo ***', 'alias': ''},
]

if sys.platform == 'linux':
    # Command that took few seconds and is killed by the system/test
    parameters.append({'LOG_FORMAT': 'command',
                       'COMMAND': 'timeout 2 tail -f /var/ossec/logs/active-responses.log', 'ALIAS': ''})
    parameters.append({'LOG_FORMAT': 'full_command',
                       'COMMAND': 'timeout 2 tail -f /var/ossec/logs/active-responses.log', 'ALIAS': ''})
    # Command with many arguments.
    parameters.append({'LOG_FORMAT': 'command', 'COMMAND': 'ss -l -p -u -t -4 -6 -n', 'ALIAS': ''})
    parameters.append({'LOG_FORMAT': 'full_command', 'COMMAND': 'ss -l -p -u -t -4 -6 -n', 'ALIAS': ''})

    metadata.append({'log_format': 'command',
                     'command': 'timeout 2 tail -f /var/ossec/logs/active-responses.log', 'alias': ''})
    metadata.append({'log_format': 'full_command',
                     'command': 'timeout 2 tail -f /var/ossec/logs/active-responses.log', 'alias': ''})
    metadata.append({'log_format': 'command',
                     'command': 'ss -l -p -u -t -4 -6 -n', 'alias': ''})
    metadata.append({'log_format': 'full_command',
                     'command': 'ss -l -p -u -t -4 -6 -n', 'alias': ''})

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['COMMAND'], x['ALIAS']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


def dbg_reading_command(command, alias, log_format):
    """Check if the (previously known) output of a command ("echo") is displayed correctly.

    It also checks if the "alias" option is working correctly.

    Args:
        command (str): Command to be monitored.
        alias (str): An alternate name for the command.
        log_format (str): Format of the log to be read ("command" or "full_command").

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
    """
    prfx = prefix
    output = command
    output = output.replace('echo ', '')

    if log_format == 'full_command':
        msg = fr"^{output}'"
        prfx = ''
    else:
        msg = fr"DEBUG: Reading command message: 'ossec: output: '{alias}': {output}'"

    wazuh_log_monitor.start(timeout=5, callback=monitoring.make_callback(pattern=msg, prefix=prfx),
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)


def dbg_read_lines(command):
    """
    Check if the "DEBUG: Read <number> lines from command <command>" line is displayed correctly.

    Args:
        command (str): Command to be monitored.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
    """
    msg = fr"lines from command '{command}'"

    wazuh_log_monitor.start(timeout=60, callback=monitoring.make_callback(pattern=msg, prefix=prefix, escape=True),
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)


def test_command_execution(get_local_internal_options, configure_local_internal_options, get_configuration,
                           configure_environment, restart_logcollector):
    """Check if the Wazuh run correctly with the specified command monitoring configuration.

    Ensure command monitoring allow the specified attributes. Also, in the case of manager instance, check if the API
    answer for localfile block coincides.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    cfg = get_configuration['metadata']

    log_callback = logcollector.callback_monitoring_command(cfg['log_format'], cfg['command'],
                                                            prefix=prefix, escape=True)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)


def test_command_execution_dbg(get_local_internal_options, configure_local_internal_options, get_configuration,
                               configure_environment, restart_logcollector):
    """Check if the debug logs are displayed correctly when the test commands are executed.

    For this purpose, the following items are tested:
        * "DEBUG: Running command '<command>'"
        * "DEBUG: Reading command message: 'ossec: output: '<command>': <output>'"
        * "DEBUG: Reading command message: 'ossec: output: '<alias_command>': <output>'"
        * "DEBUG: Read <number> lines from command <command>"

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    cfg = get_configuration['metadata']
    log_format_message = 'full command' if cfg['log_format'] == 'full_command' else 'command'
    msg = fr"DEBUG: Running {log_format_message} '{cfg['command']}'"

    wazuh_log_monitor.start(timeout=10, error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=monitoring.make_callback(pattern=msg, prefix=prefix, escape=True))

    if cfg['command'] == 'echo hello world':  # Command with known output to test "Reading command message: ..."
        dbg_reading_command(cfg['command'], cfg['alias'], cfg['log_format'])

    if cfg['log_format'] == 'command':  # "Read ... lines from command ..." only appears with log_format=command
        dbg_read_lines(cfg['command'])
