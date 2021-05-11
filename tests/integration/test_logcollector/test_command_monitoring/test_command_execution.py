# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from subprocess import check_output
from wazuh_testing.tools import monitoring, LOG_FILE_PATH
from wazuh_testing import global_parameters
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_command_conf.yaml')

local_internal_options = {
    'logcollector.remote_commands': 1,
    'logcollector.debug': 2,
    'monitord.rotate_log': 0
}

parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo hello world', 'ALIAS': 'goodbye'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'not_found_command -o option -v', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': f'tail -f {LOG_FILE_PATH}', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'ls -R /tmp', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'cat doesntexists.txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo ***', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo hello world', 'ALIAS': 'goodbye'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'not_found_command -o option -v', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': f'tail -f {LOG_FILE_PATH}', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'ls -R /tmp', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'cat doesntexists.txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo ***', 'ALIAS': ''},
]
metadata = [
    {'log_format': 'command', 'command': 'echo', 'alias': '', 'info': 'empty_output'},
    {'log_format': 'command', 'command': 'echo hello world', 'alias': 'goodbye', 'info': 'check_output_and_alias'},
    {'log_format': 'command', 'command': 'not_found_command -o option -v', 'alias': '', 'info': 'not_found'},
    {'log_format': 'command', 'command': f'tail -f {LOG_FILE_PATH}', 'alias': '', 'info': 'does not end'},
    {'log_format': 'command', 'command': 'ls -R /tmp', 'alias': '', 'info': 'long_output'},
    {'log_format': 'command', 'command': 'cat doesntexists.txt', 'alias': '', 'info': 'that_fails'},
    {'log_format': 'command', 'command': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'alias': '',
     'info': 'special_chars_filename'},
    {'log_format': 'command', 'command': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'alias': '',
     'info': 'special_chars_command'},
    {'log_format': 'command', 'command': 'echo ***', 'alias': '', 'info': 'special_chars_echo'},
    {'log_format': 'full_command', 'command': 'echo', 'alias': '', 'info': 'empty_output'},
    {'log_format': 'full_command', 'command': 'echo hello world', 'alias': 'goodbye', 'info': 'check_output_and_alias'},
    {'log_format': 'full_command', 'command': 'not_found_command -o option -v', 'alias': '', 'info': 'not_found'},
    {'log_format': 'full_command', 'command': f'tail -f {LOG_FILE_PATH}', 'alias': '', 'info': 'does not end'},
    {'log_format': 'full_command', 'command': 'ls -R /tmp', 'alias': '', 'info': 'long_output'},
    {'log_format': 'full_command', 'command': 'cat doesntexists.txt', 'alias': '', 'info': 'that_fails'},
    {'log_format': 'full_command', 'command': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'alias': '',
     'info': 'special_chars_filename'},
    {'log_format': 'full_command', 'command': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'alias': '',
     'info': 'special_chars_command'},
    {'log_format': 'full_command', 'command': 'echo ***', 'alias': '', 'info': 'special_chars_echo'},
]

if sys.platform == 'linux':
    parameters.append({'LOG_FORMAT': 'command', 'COMMAND': 'timeout 2 tail -f /dev/random', 'ALIAS': 'killed_by_test'})
    parameters.append({'LOG_FORMAT': 'full_command', 'COMMAND': 'timeout 2 tail -f /dev/random', 'ALIAS': ''})
    parameters.append({'LOG_FORMAT': 'command', 'COMMAND': 'ss -l -p -u -t -4 -6 -n', 'ALIAS': ''})
    parameters.append({'LOG_FORMAT': 'full_command', 'COMMAND': 'ss -l -p -u -t -4 -6 -n', 'ALIAS': ''})
    metadata.append({'log_format': 'command', 'command': 'timeout 2 tail -f /dev/random', 'alias': '',
                     'info': 'killed_by_test'})
    metadata.append({'log_format': 'full_command', 'command': 'timeout 2 tail -f /dev/random', 'alias': '',
                     'info': 'killed_by_test'})
    metadata.append({'log_format': 'command', 'command': 'ss -l -p -u -t -4 -6 -n', 'alias': '',
                     'info': 'many_arguments'})
    metadata.append({'log_format': 'full_command', 'command': 'ss -l -p -u -t -4 -6 -n', 'alias': '',
                     'info': 'many_arguments'})

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['log_format']}_{x['info']}" for x in metadata]


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
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
    output = check_output(command, universal_newlines=True, shell=True).strip()

    if log_format == 'full_command':
        msg = fr"^{output}'"
        prefix = ''
    else:
        msg = fr"DEBUG: Reading command message: 'ossec: output: '{alias}': {output}'"

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=monitoring.make_callback(pattern=msg, prefix=prefix),
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)


def test_command_execution(get_local_internal_options, configure_local_internal_options, get_configuration,
                           configure_environment, restart_logcollector):
    """Check if the Wazuh runs correctly by executing different commands with special characteristics.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
    """
    config = get_configuration['metadata']
    msg = config['command']

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=monitoring.make_callback(pattern=msg,
                                                              prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                              escape=True))


def test_command_execution_dbg(get_local_internal_options, configure_local_internal_options, get_configuration,
                               configure_environment, restart_logcollector):
    """Check if the debug logs are displayed correctly when the test commands are executed.

    For this purpose, it checks that the following logs are generated:  "DEBUG: Running command...",
    "DEBUG: Reading command message..." and, finally "Read ... lines from command...".

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
    """
    config = get_configuration['metadata']

    # Check log line "DEBUG: Running command '<command>'"
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=logcollector.callback_running_command(log_format=config['log_format'],
                                                                           command=config['command'],
                                                                           escape=True))

    # Command with known output to test "Reading command message: ..."
    if config['command'].startswith('echo') and config['alias'] != '':
        dbg_reading_command(config['command'], config['alias'], config['log_format'])

    # "Read ... lines from command ..." only appears with log_format=command
    if config['log_format'] == 'command':
        wazuh_log_monitor.start(timeout=60,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                                callback=logcollector.callback_read_lines(command=config['command'],
                                                                          escape=True))
