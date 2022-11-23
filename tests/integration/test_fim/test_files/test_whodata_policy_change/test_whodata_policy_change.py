'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM reports (or truncates if required)
       the changes made in monitored files when it matches the 'nodiff' tag and vice versa when
       the 'report_changes' option is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#nodiff

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
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing import global_parameters, LOG_FILE_PATH
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


# variables
test_folders = [os.path.join(PREFIX, fim.TEST_DIR_1)]
folder = test_folders[0]
file_list = [f"regular_file"]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = configuration.get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = folder
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


# tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_whodata_policy_change(configuration, metadata, set_wazuh_configuration, create_monitored_folders_function,
                                 configure_local_internal_options_function, restart_syscheck_function,
                                 wait_fim_start_function):
    '''
    description: Check if the 'wazuh-syscheckd' daemon reports the file changes (or truncates if required)
                 in the generated events using the 'nodiff' tag and vice versa. For this purpose, the test
                 will monitor a directory and make file operations inside it. Then, it will check if a
                 'diff' file is created for the modified testing file. Finally, if the testing file matches
                 the 'nodiff' tag, the test will verify that the FIM event generated contains in its
                 'content_changes' field a message indicating that 'diff' is truncated because
                 the 'nodiff' option is used.

    wazuh_min_version: 4.5.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration_fim:
            type: fixture
            brief: Set ossec.conf and local_internal_options configuration.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.
        - wait_for_fim_start_function:
            type: fixture
            brief: check that the starting fim scan is detected.

    assertions:
        - Verify that for each modified file a 'diff' file is generated.
        - Verify that FIM events include the 'content_changes' field.
        - Verify that FIM events truncate the modifications made in a monitored file
          when it matches the 'nodiff' tag.
        - Verify that FIM events include the modifications made in a monitored file
          when it does not match the 'nodiff' tag.

    input_description: A test case (ossec_conf_report) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - whodata
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Check it is being monitored in whodata
    evm.detect_windows_sacl_configured(wazuh_log_monitor, '.*')
    # Check Whodata engine has started
    evm.detect_whodata_start(wazuh_log_monitor)
    
    # Change policies
    if metadata['check_event']:
        time.sleep(6)
    command = f"auditpol /restore /file:{os.path.join(TEST_DATA_PATH,metadata['disabling_file'])}"
    output = run_local_command_returning_output(command)
    
    # Check it changes to realtime
    if metadata['check_event']:
        evm.check_fim_event(timeout=20, callback=fim.CB_RECIEVED_EVENT_4719)
    evm.detect_windows_whodata_mode_change(wazuh_log_monitor, '.*')

    # Create/Update/Delete file and check events   
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list, time_travel=False,
                     event_mode=fim.REALTIME_MODE, min_timeout=global_parameters.default_timeout*4,
                     triggers_event=True)

    # Restore policies
    command = f"auditpol /restore /file:{os.path.join(TEST_DATA_PATH,metadata['enabling_file'])}"
    run_local_command_returning_output(command)
