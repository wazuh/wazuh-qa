'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files in whodata mode, if the policies for those
       files change during runtime, the monitoring mode changes to realtime. This tests check that when the
       policies change, monitoring continues correctly in realtime and events are detected.

components:
    - FIM

suite: whodata_policy_change

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html

pytest_args:
    - fim_mode:
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_whodata_policy_change
'''
import os
import time

import pytest
from wazuh_testing.tools import PREFIX, configuration
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing import T_5, T_20, T_30, LOG_FILE_PATH
from wazuh_testing.modules import fim
from wazuh_testing.modules.fim import event_monitor as evm
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.utils import regular_file_cud


# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_whodata_policy_change.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_whodata_policy_change.yaml')

# Variables
test_folders = [os.path.join(PREFIX, fim.TEST_DIR_1)]
folder = test_folders[0]
file_list = [f"regular_file"]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
policies_file = os.path.join(TEST_DATA_PATH, 'policy_enable.csv')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = configuration.get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = folder
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


# Tests
@pytest.mark.parametrize('policies_file', [policies_file], ids='')
@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_whodata_policy_change(configuration, metadata, set_wazuh_configuration, create_monitored_folders_module,
                               configure_local_internal_options_function, policies_file, restore_win_whodata_policies,
                               restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' is monitoring a in whodata mode in Windows, and the Audit Policies are
                 changed, the monitoring changes to realtime and works on the monitored files.

    test_phases:
        - setup:
            - Set wazuh configuration.
            - Create target folder to be monitored
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Check that SACL has been configured for monitored folders
            - Change windows audit whodata policies
            - Check the change has been detected and monitoring changes to realtime mode
            - Create, Update and Delete files in the monitored folder and check events are generated in realtime
        - teardown:
            - Restore windows audit policies
            - Delete the monitored folders
            - Restore configuration
            - Stop wazuh
    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - create_monitored_folders_module:
            type: fixture
            brief: Create the folders that will be monitored, delete them after test.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options configuration.
        - policies_file:
            type: string
            brief: path for audit policies file to use on restore_win_whodata_policies fixture
        - restore_win_whodata_policies
            type: fixture
            brief: restores windows audit policies using a given csv file after yield
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.
        - wait_for_fim_start_function:
            type: fixture
            brief: check that the starting fim scan is detected.

    assertions:
        - Verify the SACL for the monitored files is configured
        - Verify Whodata monitoring has started
        - Verify that the event 4719 event is detected and changes monitoring to real-time
        - Verify the monitoring mode changes to real-time
        - Verify monitoring in real-time works correctly for the monitored files.

    input_description:
        - The file 'cases_whodata_policy_change.yaml' provides the test cases and specific configuration.
        - The file 'configuration_whodata_policy_change.yaml' provides the configuration template to be used.

    expected_output:
        - fr".*win_whodata.*The SACL of '({file})' will be configured"
        - r'.*win_whodata.*(Event 4719).*Switching directories to realtime'
        - fr".*set_whodata_mode_changes.*The '({file})' directory starts to be monitored in real-time mode."
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - whodata
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Check it is being monitored in whodata
    evm.detect_windows_sacl_configured(wazuh_log_monitor)
    # Check Whodata engine has started
    evm.detect_whodata_start(wazuh_log_monitor)

    # Change policies
    if metadata['check_event']:
        # Wait to allow thread_checker to be executed twice so Event 4719 detection starts.
        time.sleep(T_5)
    command = f"auditpol /restore /file:{os.path.join(TEST_DATA_PATH,metadata['disabling_file'])}"
    output = run_local_command_returning_output(command)

    # Check monitoring changes to realtime
    if metadata['check_event']:
        evm.check_fim_event(timeout=T_20, callback=evm.CB_RECIEVED_EVENT_4719)
    evm.detect_windows_whodata_mode_change(wazuh_log_monitor)

    # Create/Update/Delete file and check events
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list, event_mode=fim.REALTIME_MODE,
                     escaped=True, min_timeout=T_30, triggers_event=True)
