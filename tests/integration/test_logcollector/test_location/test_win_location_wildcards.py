'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages. Secifically, these
       tests check the behavior of the location tag when it is configured using wildcards. They check that the file
       detected and monitored correctly after wildcard expansion. They also check that when no file matching the regex
       is found, a message is shown in debug mode.

components:
    - logcollector

suite: location_wildcards

targets:
    - agent

daemons:
    - wazuh-agent

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
    - https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html
    - https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#logcollector

tags:
    - logcollector_options
'''
import os
import re
import pytest
from wazuh_testing.modules import TIER1, WINDOWS
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.logcollector import event_monitor as evm
from wazuh_testing.modules import logcollector as lc

pytestmark = [TIER1, WINDOWS]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Test configurations and cases data
folder_path = os.path.join(PREFIX, 'testfolder', 'subfolder')
test_file = os.path.join(folder_path, 'test')

# --------------------------------TEST_LOCATION_WILDCARDS-------------------------------------------
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_win_location_wildcards.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_win_location_wildcards.yaml')

configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                             configuration_metadata)

prefix = lc.LOG_COLLECTOR_PREFIX
local_internal_options = lc.LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS
log_sample = 'Nov 10 12:19:04 localhost sshd: test log'


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('folder_path, file_list', [(folder_path, ['test'])], ids=[''])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_win_location_wildcards(configuration, metadata, folder_path, file_list, create_files_in_folder,
                                truncate_monitored_files, set_wazuh_configuration,
                                configure_local_internal_options_function, restart_wazuh_function):
    '''
    description: Check logcollector expands wildcards and monitors target file properly.

    test_phases:
        - Setup:
           - Create file to monitor logs
           - Truncate ossec.log file
           - Set ossec.conf and local_internal_options.conf
           - Restart the wazuh daemon
        - Test:
           - Check if the wildcards expanded and matches file
           - Insert the log message.
           - Check expected response.
        - Teardown:
           - Delete the monitored file
           - Restore ossec.conf and local_internal_options.conf
           - Stop Wazuh

    wazuh_min_version: 4.5.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata
        - folder_path:
            type: str
            brief: path for folder to be created and monitored
        - files_list:
            type: List
            brief: list of filenames to be created inside folder_path
        - create_files_in_folder:
            type: fixture
            brief: Create a list of files file inside target folder
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options file.
        - restart_wazuh_function:
            type: fixture
            brief: Restart wazuh.

    assertions:
        - Check that when configuring location with wildcards it expands and matches file
        - Check that logcollector is analyzing the log file.
        - Check that logs are ignored when they match with configured regex

    input_description:
        - The `configuration_win_location_wildcards.yaml` file provides the module configuration for this test.
        - The `cases_win_location_wildcards` file provides the test cases.

    expected_output:
        - r".*wazuh-agent.*expand_win32_wildcards.*DEBUG: No file/folder that matches {regex}"
        - r".*wazuh-agent.*check_pattern_expand.*New file that matches the '{file_path}' pattern: '(.*)'"
        - r".*wazuh-agent.*Analizing file: '{file}'.*"
        - r".*wazuh-agent.*DEBUG: Reading syslog '{message}'.*"
    '''
    command = f"echo {log_sample}>> {test_file}"
    file = re.escape(test_file)

    if not metadata['matches']:
        # If it does not match, check that message shows no matching file was found
        evm.check_win_wildcard_pattern_no_match(re.escape(metadata['location']), prefix)
    else:
        # Check that pattern is expanded to configured file
        evm.check_wildcard_pattern_expanded(file, re.escape(metadata['location']), prefix)

        # Check log file is being analized
        evm.check_analyzing_file(file=file, prefix=prefix)

        # Insert log
        run_local_command_returning_output(command)

        # Check the log is read from the monitored file
        evm.check_syslog_message(message=log_sample, prefix=prefix)
