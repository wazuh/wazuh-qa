'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The wazuh-analysisd daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. The 'if_sid' option is used to
       associate a rule to a parent rule by referencing the rule ID of the parent. This test module checks that when
       an valid rule_id is used, the rule is not ignored.

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

from wazuh_testing import LOG_FILE_PATH, T_5, T_10
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.analysisd import event_monitor as ev


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
RULES_SAMPLE_PATH = os.path.join(TEST_DATA_PATH, 'rules_samples')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# ----------------------------------------TEST_VALID_SIGNATURE_ID------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_signature_id_values.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_valid_signature_id.yaml')

# test_valid_signature_id configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ----------------------------------------TEST_INVALID_SIGNATURE_ID------------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_signature_id_values.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_signature_id.yaml')

# test_empty_signature_id configurations
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# ----------------------------------------TEST_NULL_SIGNATURE_ID------------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_signature_id_values.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_null_signature_id.yaml')

# test_null_signature_id configurations
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_valid_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                            prepare_custom_rules_file, restart_wazuh_function):
    '''
    description: Check that when a rule has an valid signature ID value assigned to the if_sid option, the rule is
                 not ignored.

    test_phases:
        - Setup:
            - Set wazuh configuration.
            - Copy custom rules file into manager
            - Clean logs files and restart wazuh to apply the configuration.
        - Test:
            - Check no log for "if_sid not found" is detected
            - Check no log for "empty if_sid" is detected
            - Check no log for "invalid if_sid" is detected
        - Tierdown:
            - Delete custom rule file
            - Restore configuration
            - Stop wazuh

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
        - prepare_custom_rules_file:
            type: fixture
            brief: Copies custom rules_file before test, deletes after test.
        - restart_wazuh_function:
            type: fixture
            brief: Restart wazuh at the start of the module to apply configuration.

    assertions:
        - Check that wazuh starts
        - Check ".*Signature ID '(\\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\\d*)'" event
        - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

    input_description:
        - The `configuration_signature_id_values.yaml` file provides the module configuration for
          this test.
        - The `cases_signature_id_values.yaml` file provides the test cases.
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Check that no log appears for rules if_sid field pointing to a non existent SID
    with pytest.raises(TimeoutError):
        ev.check_if_sid_not_found(wazuh_log_monitor)
    # Check that no log appears for rules if_sid field being empty string
    with pytest.raises(TimeoutError):
        ev.check_empty_if_sid(wazuh_log_monitor)
    # Check that no log appears for rules if_sid field being invalid
    with pytest.raises(TimeoutError):
        ev.check_invalid_if_sid(wazuh_log_monitor, is_empty=False)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_invalid_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                              prepare_custom_rules_file, restart_wazuh_function):
    '''
    description: Check that when a rule has an empty or invalid signature ID value (invalid format) assigned to the
                 if_sid option, the rule is ignored.

    test_phases:
        - Setup:
            - Set wazuh configuration.
            - Copy custom rules file into manager
            - Clean logs files and restart wazuh to apply the configuration.
        - Test:
            - Check "invalid if_sid" log is detected
        - Tierdown:
            - Delete custom rule file
            - Restore configuration
            - Stop wazuh


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
        - prepare_custom_rules_file:
            type: fixture
            brief: Copies custom rules_file before test, deletes after test.
        - restart_wazuh_function:
            type: fixture
            brief: Restart wazuh at the start of the module to apply configuration.

    assertions:
        - Check that wazuh starts
        - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

    input_description:
        - The `configuration_signature_id_values.yaml` file provides the module configuration for
          this test.
        - The `cases_empty_signature_id.yaml` file provides the test cases.
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Check that expected log appears for rules if_sid field being invalid
    ev.check_invalid_if_sid(wazuh_log_monitor, metadata['is_empty'])


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_null_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                           prepare_custom_rules_file, restart_wazuh_function):
    '''
    description: Check that when a rule has an invalid signature ID value, that references a nonexisten rule,
                 assigned to the if_sid option, the rule is ignored.

    test_phases:
        - setup:
            - Set wazuh configuration.
            - Copy custom rules file into manager
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Check "if_sid not found" log is detected
            - Check "empty if_sid" log is detected
        - teardown:
            - Delete custom rule file
            - Restore configuration
            - Stop wazuh

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
        - prepare_custom_rules_file:
            type: fixture
            brief: Copies custom rules_file before test, deletes after test.
        - restart_wazuh_function:
            type: fixture
            brief: Restart wazuh at the start of the module to apply configuration.

    assertions:
        - Check that wazuh starts
        - Check ".*Signature ID '(\\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\\d*)'" event
        - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

    input_description:
        - The `configuration_signature_id_values.yaml` file provides the module configuration for
          this test.
        - The `cases_signature_id_values.yaml` file provides the test cases.
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Check that expected log appears for rules if_sid field pointing to a non existent SID
    ev.check_if_sid_not_found(wazuh_log_monitor)
    # Check that expected log appears for rules if_sid field being empty (empty since non-existent SID is ignored)
    ev.check_empty_if_sid(wazuh_log_monitor)
