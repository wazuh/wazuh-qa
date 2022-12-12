'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The wazuh-analysisd daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. The 'if_sid' option is used to
       associate a rule to a parent rule by referencing the rule ID of the parent. This test module checks that when
       an invalid (empty or invalid format) rule_id is used, the rule is ignored.

components:
    - analysisd

suite: analysisd

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

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

references:
    - https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-sid
'''
import os
import pytest
from shutil import chown, copy

from wazuh_testing import LOG_FILE_PATH, T_10
from wazuh_testing.tools import CUSTOM_RULES_PATH, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import delete_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools.services import control_service
from wazuh_testing.modules.analysisd.event_monitor import CB_INVALID_IF_SID_RULE_IGNORED, ERR_MSG_INVALID_IF_SID


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
RULES_SAMPLE_PATH = os.path.join(TEST_DATA_PATH, 'rules_samples')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_signature_id_values.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_signature_id.yaml')

# test_empty_signature_id configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_invalid_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                              restart_wazuh_module):
    '''
    description: Check that when a rule has an empty or invalid signature ID value (invalid format) assigned to the
                 if_sid option, the rule is ignored.

    test_phases:
        - Copy custom rule file into manager
        - Restart manager
        - Check logs
        - Check analysisd is running

    wazuh_min_version: 4.4.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.

    assertions:
        - Check that wazuh starts
        - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

    input_description:
        - The `configuration_signature_id_values.yaml` file provides the module configuration for
          this test.
        - The `cases_empty_signature_id.yaml` file provides the test cases.
    '''

    rules_file_path = os.path.join(RULES_SAMPLE_PATH, metadata['rules_file'])
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Copy rules to manager folder
    copy(rules_file_path, CUSTOM_RULES_PATH)
    chown(os.path.join(CUSTOM_RULES_PATH, metadata['rules_file']), WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)

    # Restart wazuh for changes to take effect
    control_service(action='restart')

    # Check logs
    if metadata['is_empty']:
        callback = fr".*Invalid 'if_sid' value: ''. Rule '(\d*)' will be ignored.*"
    else:
        callback = CB_INVALID_IF_SID_RULE_IGNORED
    wazuh_log_monitor.start(timeout=T_10, callback=generate_monitoring_callback(callback),
                            error_message=ERR_MSG_INVALID_IF_SID)

    # Delete rules file to clean enviroment
    delete_file(os.path.join(CUSTOM_RULES_PATH, metadata['rules_file']))
