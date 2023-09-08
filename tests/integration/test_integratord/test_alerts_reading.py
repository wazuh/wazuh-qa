'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Integratord manages Wazuh integrations with other applications such as Yara or Slack, by feeding
the integrated aplications with the alerts located in alerts.json file. This test module aims to validate that
given a specific alert, the expected response is recieved, depending if it is a valid/invalid json alert, an
overlong alert (64kb+) or what happens when it cannot read the file because it is missing.

components:
    - integratord

suite: test_integratord

targets:
    - manager

daemons:
    - wazuh-integratord

os_platform:
    - Linux

os_version:
    - Centos 8
    - Ubuntu Focal

references:
    - https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html#slack
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html

pytest_args:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - slack
'''
import os
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, ALERT_FILE_PATH
from wazuh_testing.tools.file import remove_file, copy
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing.modules import integratord as integrator
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.integratord import event_monitor as evm


def replace_webhook_url(ids, configurations):
    '''Replace the Webhook URL in each test case configuration parameters.

    Args:
        ids (list): List of ids of test cases.
        configurations (list): List of test's configuration parameters.

    Returns:
        configurations (list): List of configurations.
    '''
    for i in range(0, len(ids)):
        configurations[i]['WEBHOOK_URL'] = global_parameters.slack_webhook_url

    return configurations


# Marks
pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and test cases paths
configurations_template = os.path.join(CONFIGURATIONS_PATH, 'configuration_alerts_reading.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_integratord_change_inode_alert.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_integratord_read_valid_json_alerts.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_integratord_read_invalid_json_alerts.yaml')

# Get configurations and test cases
t1_config_params, t1_metadata, t1_cases_ids = get_test_cases_data(t1_cases_path)
t2_config_params, t2_metadata, t2_cases_ids = get_test_cases_data(t2_cases_path)
t3_config_params, t3_metadata, t3_cases_ids = get_test_cases_data(t3_cases_path)

t1_config_params = replace_webhook_url(t1_cases_ids, t1_config_params)
t2_config_params = replace_webhook_url(t2_cases_ids, t2_config_params)
t3_config_params = replace_webhook_url(t3_cases_ids, t3_config_params)

# Load tests configurations
t1_config = load_configuration_template(configurations_template, t1_config_params, t1_metadata)
t2_config = load_configuration_template(configurations_template, t2_config_params, t2_metadata)
t3_config = load_configuration_template(configurations_template, t3_config_params, t3_metadata)

# Variables
TEMP_FILE_PATH = os.path.join(WAZUH_PATH, 'logs/alerts/alerts.json.tmp')
daemons_handler_configuration = {'daemons': integrator.REQUIRED_DAEMONS}
local_internal_options = {'integrator.debug': '2', 'analysisd.debug': '1', 'monitord.rotate_log': '0'}


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t1_config, t1_metadata), ids=t1_cases_ids)
def test_integratord_change_json_inode(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                       configure_local_internal_options_module, daemons_handler_function,
                                       wait_for_start_module):
    '''
    description: Check that wazuh-integratord detects a change in the inode of the alerts.json and continues reading
                 alerts.

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate Wazuh's logs.
            - Configure internal options.
            - Restart the daemons defined in `daemons_handler_configuration`.
            - Wait for the restarted modules to start correctly.
        - test:
            - Wait until integratord is ready to read alerts.
            - Insert an alert in the `alerts.json` file.
            - Check if the alert was received by Slack.
            - Replace the `alerts.json` file while wazuh-integratord is reading it.
            - Wait for the inode change to be detected by wazuh-integratord.
            - Check if wazuh-integratord detects that the file's inode has changed.
            - Insert an alert in the `alerts.json` file.
            - Check if the alert is processed.
            - Check alert was received by Slack.
        - teardown:
            - Truncate Wazuh's logs.
            - Restore initial configuration, both `ossec.conf` and `local_internal_options.conf`.

    wazuh_min_version: 4.3.5

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
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_json_alerts` file provides the test cases.

    expected_output:
        - r'.+wazuh-integratord.*DEBUG: jqueue_next.*Alert file inode changed.*'
        - r'.+wazuh-integratord.*Processing alert.*'
        - r'.+wazuh-integratord.*<Response [200]>'
    '''
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)
    command = f"echo '{metadata['alert_sample']}' >> {ALERT_FILE_PATH}"

    # Wait until integratord is ready to read alerts
    time.sleep(integrator.TIME_TO_DETECT_FILE)

    # Insert a new alert
    run_local_command_returning_output(command)

    evm.check_third_party_response(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout)

    # Change file to change inode
    copy(ALERT_FILE_PATH, TEMP_FILE_PATH)
    remove_file(ALERT_FILE_PATH)
    copy(TEMP_FILE_PATH, ALERT_FILE_PATH)

    # Wait for Inode change to be detected
    # The `integratord` library tries to read alerts from the file every 1 second. So, the test waits 1 second + 1
    # until the file is reloaded.
    time.sleep(integrator.TIME_TO_DETECT_FILE)

    evm.check_file_inode_changed(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout)

    # Insert a new alert
    run_local_command_returning_output(command)

    # Check if the alert was correctly sent to Slack
    evm.check_third_party_response(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t2_config, t2_metadata), ids=t2_cases_ids)
def test_integratord_read_valid_alerts(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                       configure_local_internal_options_module, daemons_handler_function,
                                       wait_for_start_module):
    '''
    description: Check that when a given alert is inserted into alerts.json, integratord works as expected. In case
    of a valid alert, a slack integration alert is expected in the alerts.json file.

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate Wazuh's logs.
            - Configure internal options.
            - Restart the daemons defined in `daemons_handler_configuration`.
            - Wait for the restarted modules to start correctly.
        - test:
            - Insert a valid alert in the alerts.json file.
            - Check if the alert was received by Slack correctly (HTTP response status code: 200)
        - teardown:
            - Truncate Wazuh's logs.
            - Restore initial configuration, both `ossec.conf` and `local_internal_options.conf`.

    wazuh_min_version: 4.3.7

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
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_valid_json_alerts` file provides the test cases.

    expected_output:
        - r'.+wazuh-integratord.*alert_id.*\"integration\": \"slack\".*'
    '''
    sample = metadata['alert_sample']
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    run_local_command_returning_output(f"echo '{sample}' >> {ALERT_FILE_PATH}")

    # Read Response in ossec.log
    evm.check_third_party_response(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t3_config, t3_metadata), ids=t3_cases_ids)
def test_integratord_read_invalid_alerts(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                         configure_local_internal_options_module, daemons_handler_function,
                                         wait_for_start_module):
    '''
    description: Check that when a given alert is inserted into alerts.json, integratord works as expected. If the alert
                 is invalid, broken, or overlong a message will appear in the ossec.log file.

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate Wazuh's logs.
            - Configure internal options.
            - Restart the daemons defined in `daemons_handler_configuration`.
            - Wait for the restarted modules to start correctly.
        - test:
            - Insert an invalid alert in the alerts.json file.
            - Check if wazuh-integratord process the alert and report an error.
        - teardown:
            - Truncate Wazuh's logs.
            - Restore initial configuration, both `ossec.conf` and `local_internal_options.conf`.

    wazuh_min_version: 4.3.7

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
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_invalid_json_alerts` file provides the test cases.

    expected_output:
        - r'.+wazuh-integratord.*WARNING: Invalid JSON alert read.*'
        - r'.+wazuh-integratord.*WARNING: Overlong JSON alert read.*'

    '''
    sample = metadata['alert_sample']
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    if metadata['alert_type'] == 'invalid':
        callback = integrator.CB_INVALID_ALERT_READ
    else:
        callback = integrator.CB_OVERLONG_ALERT_READ
        # Add 90kb of padding to alert to make it go over the allowed value of 64KB.
        padding = "0" * 90000
        sample = sample.replace("padding_input", "agent_" + padding)

    run_local_command_returning_output(f"echo '{sample}' >> {ALERT_FILE_PATH}")

    # Read Response in ossec.log
    evm.check_invalid_alert_read(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout,
                                 callback=callback,
                                 error_message=f"Did not recieve the expected '{callback}' event")
