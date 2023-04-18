'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Integratord manages wazuh integrations with other applications such as Yara or Virustotal, by feeding
the integrated aplications with the alerts located in alerts.json file. This test module aims to validate that
given a specific alert, the expected response is recieved, depending if it is a valid/invalid json alert, an
overlong alert (64kb+) or what happens when it cannot read the file because it is missing.

components:
    - integratord

suite: integratord_read_json_alerts

targets:
    - agent

daemons:
    - wazuh-integratord

os_platform:
    - Linux

os_version:
    - Centos 8
    - Ubuntu Focal

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/virustotal-scan/integration.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.htm

pytest_args:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - virustotal
'''
import os
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.modules.integratord import event_monitor as evm
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor


# Marks
pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'config_integration_no_option_tag.yaml')
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'config_slack_options.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_integration_no_option_tag.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_slack_options.yaml')

# Configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configuration_parameters[0]['HOOK_URL'] = global_parameters.slack_webhook_url
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
for config_params in t2_configuration_parameters:
    config_params['HOOK_URL'] = global_parameters.slack_webhook_url
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

local_internal_options = {'integrator.debug': '2'}


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata',
                         zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_integration_no_option_tag(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                       configure_local_internal_options_module, restart_wazuh_daemon_function,
                                       wait_for_start_module):
    '''
    description: Check that when a given alert is inserted into alerts.json, integratord works as expected. In case
    of a valid alert, a virustotal integration alert is expected in the alerts.json file.
    wazuh_min_version: 4.3.7

    test_phases:
        - Insert an alert alerts.json file.
        - Check virustotal response is added in ossec.log

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
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart wazuh daemon before starting a test.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `config_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_valid_json_alerts` file provides the test cases.

    expected_output:
        - r'.*wazuh-integratord.*alert_id.*\"integration\": \"virustotal\".*'
    '''
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    # Read Response in ossec.log
    evm.detect_integration_enabled(integration=metadata['integration'], file_monitor=wazuh_monitor)
        
    evm.detect_options_json_file_does_not_exist(file_monitor=wazuh_monitor)
    
    evm.get_message_sent(integration='Slack', file_monitor=wazuh_monitor)
    
    evm.detect_integration_response_code(response=metadata['response_code'], file_monitor=wazuh_monitor)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata',
                         zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_slack_options(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                       configure_local_internal_options_module, restart_wazuh_daemon_function,
                                       wait_for_start_module):
    '''
    description: Check that when a given alert is inserted into alerts.json, integratord works as expected. In case
    of a valid alert, a virustotal integration alert is expected in the alerts.json file.
    wazuh_min_version: 4.5.0

    test_phases:
        - Insert an alert alerts.json file.
        - Check virustotal response is added in ossec.log

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
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart wazuh daemon before starting a test.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `config_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_valid_json_alerts` file provides the test cases.

    expected_output:
        - r'.*wazuh-integratord.*alert_id.*\"integration\": \"virustotal\".*'
    '''
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    # Read Response in ossec.log
    evm.detect_integration_enabled(integration=metadata['integration'], file_monitor=wazuh_monitor)
    if not metadata['sends_message']:
        evm.detect_unable_to_run_integration(integration=metadata['integration'], file_monitor=wazuh_monitor)
        
    else:
        message = evm.get_message_sent(integration='Slack', file_monitor=wazuh_monitor)
        if metadata['added_option'] is not None:
            assert metadata['added_option'] in message, "Error1"

        evm.detect_integration_response_code(response=metadata['response_code'], file_monitor=wazuh_monitor)
