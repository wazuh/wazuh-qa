'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration
brief: Integratord manages wazuh integrations with other applications such as Yara or Slack, by feeding
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
from wazuh_testing.tools import LOG_FILE_PATH, ALERT_FILE_PATH
from wazuh_testing.tools.file import remove_file
from wazuh_testing.modules import integratord as integrator
from wazuh_testing.modules.integratord.event_monitor import check_integratord_event
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator


# Marks
pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_integratord_read_json_alerts.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_integratord_read_json_file_deleted.yaml')

# Configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configuration_parameters[0]['WEBHOOK_URL'] = global_parameters.slack_webhook_url
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                             configuration_metadata)
local_internal_options = {'integrator.debug': '2', 'analysisd.debug': '1', 'monitord.rotate_log': '0'}

# Variables
REQUIRED_DAEMONS = integrator.REQUIRED_DAEMONS


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_integratord_read_json_file_deleted(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                            configure_local_internal_options_module, restart_wazuh_function,
                                            wait_for_start_module):
    '''
    description: Check that integratord reads the alerts.json file and, when the file is deleted, the expected
                 warning message is shown. Then, the file is created and alerts are inserted, check if integratord
                 keeps working and alerts are read.

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
        - restart_wazuh_function:
            type: fixture
            brief: Restart a list of daemons (defined in REQUIRED_DAEMONS variable) and stop them after finishing.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_json_file_deleted` file provides the test cases.

    expected_output:
        - r'.*wazuh-integratord.*WARNING.*Could not retrieve information of file.*'
        - r'.*wazuh-integratord.*Response [200].*'
    '''
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    command = f"touch {ALERT_FILE_PATH} && chmod 640 {ALERT_FILE_PATH} && chown wazuh:wazuh {ALERT_FILE_PATH}"

    # Delete alerts.json file
    remove_file(ALERT_FILE_PATH)
    check_integratord_event(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout*2,
                            callback=callback_generator(integrator.CB_CANNOT_RETRIEVE_JSON_FILE),
                            error_message=integrator.ERR_MSG_CANNOT_RETRIEVE_MSG_NOT_FOUND)

    # Create alerts.json file
    run_local_command_returning_output(command)

    # Waiting time so Integrator detects the file before the insertion
    time.sleep(integrator.TIME_TO_DETECT_FILE)

    # Insert alert to the alerts.json
    run_local_command_returning_output(f"echo '{metadata['alert_sample']}' >> {ALERT_FILE_PATH}")

    # Read Response in ossec.log
    check_integratord_event(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout*2,
                            callback=callback_generator(integrator.CB_SLACK_ALERT),
                            error_message=integrator.ERR_MSG_SLACK_ALERT_NOT_DETECTED)
