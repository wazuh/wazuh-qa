'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, these tests check the behavior of the restrict and ignore options, that allow
       users to configure regex patterns that limit if a log will be sent to analysis or will be ignored.
       The restrict causes any log that does not match the regex to be ignored, conversely, the 'ignore' option
       causes logs that match the regex to be ignored and not be sent for analysis.

components:
    - logcollector

suite: log_filter_options

targets:
    - agent
    - manager

daemons:
    - wazuh-logcollector

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
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
import sys
import re
import pytest

from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.services import get_service
from wazuh_testing.modules.logcollector import event_monitor as evm
from wazuh_testing.modules import logcollector as lc


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_restrict_ignore_regex_values.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_restrict_ignore_regex_values.yaml')

# Test configurations
test_file = os.path.join(PREFIX, 'test')

configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['LOCATION'] = test_file
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)
prefix = lc.LOG_COLLECTOR_PREFIX
local_internal_options = lc.LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('new_file_path,', [test_file], ids=[''])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_restrict_ignore_regex_values(configuration, metadata, new_file_path, create_file, truncate_monitored_files,
                                      set_wazuh_configuration, configure_local_internal_options_function,
                                      restart_wazuh_function):
    '''
    description: Check if logcollector reads or ignores a log according to a regex configured in the restrict and
                 restrict tag tag for a given log file, with each configured value for the restrict 'type' attribute
                 value configured.

    test_phases:
        - Setup:
           - Create file to monitor logs
           - Truncate ossec.log file
           - Set ossec.conf and local_internal_options.conf
           - Restart the wazuh daemon
        - Test:
           - Insert the log message.
           - Check expected response.
        - Teardown:
           - Delete the monitored file
           - Restore ossec.conf and local_internal_options.conf
           - Stop Wazuh

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata
        - new_file_path:
            type: str
            brief: path for the log file to be created and deleted after the test.
        - create_file:
            type: fixture
            brief: Create an empty file for logging
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
        - Check that logcollector is analyzing the log file.
        - Check that logs are ignored when they do not match with configured regex

    input_description:
        - The `configuration_restrict_ignore_regex_values.yaml` file provides the module configuration for this test.
        - The `cases_restrict_ignore_regex_values.yaml` file provides the test cases.

    expected_output:
        - r".*wazuh-logcollector.*Analizing file: '{file}'.*"
        - r".*wazuh-logcollector.*DEBUG: Reading syslog '{message}'.*"
        - r".*wazuh-logcollector.*DEBUG: Ignoring the log line '{message}' due to {tag} config: '{regex}'"
    '''
    log = metadata['log_sample']
    command = f"echo {log}>> {test_file}"

    file = re.escape(test_file) if sys.platform == 'win32' else test_file

    # Check log file is being analized
    evm.check_analyzing_file(file=file, prefix=prefix)

    # Insert log
    run_local_command_returning_output(command)
    # Check the log is read from the monitored file
    evm.check_syslog_message(message=log, prefix=prefix)

    # Check responses
    # If it matches with ignore, it should ignore the log due to ignore config
    if 'ignore' in metadata['matches']:
        evm.check_ignore_restrict_message(message=log, regex=metadata['ignore_regex'], tag='ignore',
                                          prefix=prefix)
        if 'restrict' in metadata['matches']:
            evm.check_ignore_restrict_message_not_found(message=log, regex=metadata['restrict_regex'], tag='restrict',
                                                        prefix=prefix)

    # If matches with restrict, it should not be ignored due to restrict config
    elif metadata['matches'] == 'restrict':
        evm.check_ignore_restrict_message_not_found(message=log, regex=metadata['restrict_regex'], tag='restrict',
                                                    prefix=prefix)
        evm.check_ignore_restrict_message_not_found(message=log, regex=metadata['ignore_regex'], tag='ignore',
                                                    prefix=prefix)

    # If it matches with None, the log should be ignored due to restrict config and not due to ignore config
    else:
        evm.check_ignore_restrict_message_not_found(message=log, regex=metadata['ignore_regex'], tag='ignore',
                                                    prefix=prefix)
        evm.check_ignore_restrict_message(message=log, regex=metadata['restrict_regex'], tag='restrict',
                                          prefix=prefix)
