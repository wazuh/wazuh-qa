'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files are
       added, modified or deleted. Specifically, these tests will check that FIM is able to monitor Windows system
       folders. FIM can redirect %WINDIR%/Sysnative monitoring toward System32 folder, so the tests also check that
       when monitoring Sysnative the path is converted to system32 and events are generated there properly.

components:
    - fim

suite: windows_system_folder_redirection

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
        scheduled: File monitoring is done after every configured interval elapses.
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - windows_folder_redirection
'''
import os


import pytest
from wazuh_testing import LOG_FILE_PATH, T_10, T_60
from wazuh_testing.tools import PREFIX, configuration
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import TEST_DIR_1
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import check_fim_event, CB_FIM_PATH_CONVERTED
from wazuh_testing.modules.fim.utils import regular_file_cud


# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_windows_system_folder_redirection.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_windows_system_folder_redirection.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = configuration.get_test_cases_data(test_cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)

# Variables
test_folders = [os.path.join(PREFIX, 'windows', 'System32', TEST_DIR_1),
                os.path.join(PREFIX, 'windows', 'SysWOW64', TEST_DIR_1)]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_windows_system_monitoring(configuration, metadata, test_folders, set_wazuh_configuration,
                                   create_monitored_folders_module, configure_local_internal_options_function,
                                   restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' monitors the windows system folders (System32 and SysWOW64) properly,
    and that monitoring for Sysnative folder is redirected to System32 and works properly.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - In case of monitoring Sysnative, check it is redirected to System32.
            - Create, Update and Delete files in monitored folders, and check logs appear.
        - teardown:
            - Delete custom monitored folder
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
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting FIM scan is detected.

    assertions:
        - Verify that for each modified file a 'diff' file is generated.
        - Verify that FIM events include the 'content_changes' field.
        - Verify that FIM events truncate the modifications made in a monitored file
          when it matches the 'nodiff' tag.
        - Verify that FIM events include the modifications made in a monitored file
          when it does not match the 'nodiff' tag.

    input_description: The file 'configuration_windows_system_folder_redirection.yaml' provides the configuration
                       template.
                       The file 'cases_windows_system_folder_redirection.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*fim_adjust_path.*Convert '(.*) to '(.*)' to process the FIM events.'
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)'
    '''
    file_list = [f"regular_file"]
    folder = os.path.join(PREFIX, 'windows', metadata['folder'], TEST_DIR_1)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # If monitoring sysnative, check redirection log message
    if metadata['redirected']:
        check_fim_event(callback=CB_FIM_PATH_CONVERTED, timeout=T_10)

    # Create, Update and Delete files in monitored folder and check expected events are generated
    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list, min_timeout=T_60, triggers_event=True,
                     escaped=True)
