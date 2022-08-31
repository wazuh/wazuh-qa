'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, these tests will check if commands with different characteristics are executed
       correctly by the logcollector. They will also check if the 'info' and 'debug' lines are
       written in the logs when running these commands.
       Log data collection is the real-time process of making sense out of the records generated by
       servers or devices. This component can receive logs through text files or Windows event logs.
       It can also directly receive logs via remote syslog which is useful for firewalls and
       other such devices.

components:
    - logcollector

suite: command_monitoring

targets:
    - agent
    - manager

daemons:
    - wazuh-logcollector

os_platform:
    - linux
    - macos
    - solaris

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#command
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#alias
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#log-format

tags:
    - logcollector_cmd_exec
'''

import os
import pytest
import sys

from subprocess import check_output
from wazuh_testing.tools import monitoring
from wazuh_testing import global_parameters
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX
import tempfile

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_command_conf.yaml')

local_internal_options = {
    'logcollector.remote_commands': '1',
    'logcollector.max_lines': '100',
    'logcollector.debug': '2'
}


parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo hello world', 'ALIAS': 'goodbye'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'not_found_command -o option -v', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'for ((i=0;;i++)); do echo "Line ${i}"; done', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'ls -R /tmp', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'cat doesntexists.txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'cat "ñ", "テスト", "ИСПЫТАНИЕ", "测试", "اختبار".txt', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'テ``ñスト, ИСПЫТА´НИЕ",\'测`试", "اختبا', 'ALIAS': ''},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo ***', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo hello world', 'ALIAS': 'goodbye'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'not_found_command -o option -v', 'ALIAS': ''},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'for ((i=0;;i++)); do echo "Line ${i}"; done', 'ALIAS': ''},
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
    {'log_format': 'command', 'command': 'for ((i=0;;i++)); do echo "Line ${i}"; done', 'alias': '',
     'info': 'does_not_end'},
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
    {'log_format': 'full_command', 'command': 'for ((i=0;;i++)); do echo "Line ${i}"; done', 'alias': '',
     'info': 'does not end'},
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


@pytest.mark.skip("This test needs refactor/fixes. Has flaky behaviour. Skipped by Issue #3218")
def test_command_execution_dbg(configure_local_internal_options_module, get_configuration, file_monitoring,
                               configure_environment, restart_logcollector):
    '''
    description: Check if the 'wazuh-logcollector' daemon generates debug logs when running commands with
                 special characteristics. For this purpose, the test will configure the logcollector to run
                 a command, setting it in the 'command' tag and using the 'command' and 'full_command' log
                 formats. The properties of that command can be, for example, a non-existent command or one
                 that includes special characters. Once the logcollector has started, it will wait for the
                 'running' event that indicates that the command has been executed. Finally, the test
                 will verify that the debug 'read N lines' event is generated, this event indicates the number
                 of lines read from the command run. Depending on test case, the test also will verify that
                 the debug event 'reading command' is generated, this event includes the output of the command
                 run, and its alias if it is set in the 'alias' tag.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_logcollector:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the debug 'running' event is generated when running the command set in the 'command' tag.
        - Verify that the debug 'reading command' event is generated when running the related command.
        - Verify that the debug 'lines' event is generated when running the related command.

    input_description: A configuration template (test_command_execution) is contained in an external
                       YAML file (wazuh_command_conf.yaml), which includes configuration settings for
                       the 'wazuh-logcollector' daemon and, it is combined with the test cases
                       (log formats and commands to run) defined in the module.

    expected_output:
        - r'DEBUG: Running .*'
        - r'DEBUG: Reading command message.*'
        - r'lines from command .*'

    tags:
        - logs
    '''
    config = get_configuration['metadata']

    # Check log line "DEBUG: Running command '<command>'"
    log_monitor.start(timeout=global_parameters.default_timeout,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                      callback=logcollector.callback_running_command(log_format=config['log_format'],
                                                                     command=config['command'],
                                                                     escape=True))

    # Command with known output to test "Reading command message: ..."
    if config['command'].startswith('echo') and config['alias'] != '':
        dbg_reading_command(config['command'], config['alias'], config['log_format'])

    # "Read ... lines from command ..." only appears with log_format=command
    if config['log_format'] == 'command':
        log_monitor.start(timeout=global_parameters.default_timeout,
                          error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                          callback=logcollector.callback_read_lines(command=config['command'],
                                                                    escape=True))
