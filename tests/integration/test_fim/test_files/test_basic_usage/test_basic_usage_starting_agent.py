'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events of type 'modified' and
       'deleted' are generated when files that exist before starting the Wazuh agent are modified.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_basic_usage

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_basic_usage
'''
import os

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.file import modify_file_content, delete_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import (callback_detect_file_modified_event, callback_detect_file_deleted_event,
                                                     ERR_MSG_FIM_EVENT_NOT_RECIEVED)
from wazuh_testing.modules.fim.classes import validate_event
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = pytest.mark.tier(level=0)

# Variables
test_folders = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_folders)
testdir1 = test_folders[0]
file_list = [{'type': REGULAR, 'path': testdir1, 'name':'regular0', 'content':''}]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_basic_usage_starting_agent.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_basic_usage.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = directory_str
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('file_list', [file_list], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_events_from_existing_files(configuration, metadata, test_folders, file_list, set_wazuh_configuration,
                                    create_files_before_test, create_monitored_folders, 
                                    configure_local_internal_options_function, restart_syscheck_function,
                                    wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'modified' and 'deleted' events when modifying
                 files that exist before the Wazuh agent is started. For this purpose, the test will modify
                 the testing file, change the system time to the next scheduled scan, and verify that
                 the proper FIM event is generated. Finally, the test will perform
                 the above steps but deleting the testing file.

        test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Create files in monitored folder
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Modify the file and check events are generated as expected
            - Delete the file and check that events are generated as expected.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.2.0

    tier: 0

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
        - file_list:
            type: dict
            brief: List of files to be created before test starts.
        - create_files_before_test:    
            type: fixture
            brief: create a given list of files before the test starts.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders:
            type: fixture
            brief: Create a given list of folders when the test starts. Delete the folders at the end of the module.
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
        - Verify that FIM events of type 'modified' and 'deleted' are generated
          when files that exist before starting the Wazuh agent are modified.


    input_description: The file 'configuration_basic_usage.yaml' provides the configuration
                       template.
                       The file 'cases_basic_usage_move_dir.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('modified' and 'deleted' events)

    tags:
        - scheduled
        - realtime
        - whodata
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    mode = metadata['fim_mode']
    filename = metadata['filename']
    folder = test_folders[metadata['folder_id']]

    # Modify file
    modify_file_content(folder, filename, new_content='Sample content')

    # Expect modified event
    modified_event = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_file_modified_event,
                                             error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
    assert 'modified' in modified_event['data']['type'] and \
           os.path.join(folder, filename) in modified_event['data']['path']
    validate_event(modified_event, mode=mode)

    # Delete file
    delete_file(os.path.join(folder, filename))

    # Expect deleted event
    deleted_event = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_file_deleted_event,
                                            error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
    assert 'deleted' in deleted_event['data']['type'] and \
           os.path.join(testdir1, filename) in deleted_event['data']['path']
    validate_event(deleted_event, mode=mode)
