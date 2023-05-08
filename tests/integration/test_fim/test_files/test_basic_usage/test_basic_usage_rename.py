'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events of type 'added' and 'deleted'
       are generated when monitored directories or files are renamed.
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
import shutil

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.file import create_file, rename_file  
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import callback_detect_event, ERR_MSG_FIM_EVENT_NOT_RECIEVED
from wazuh_testing.modules.fim.classes import validate_event
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_folders = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_folders)
test_folders.append(os.path.join(test_folders[0], 'subdir'))
new_name = 'this_is_a_new_name'
old_name = 'old_name'


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_basic_usage_rename.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_basic_usage.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = directory_str
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_rename(configuration, metadata, test_folders, set_wazuh_configuration, create_monitored_folders,
                configure_local_internal_options_function, restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when renaming directories or files.
                 When changing directory or file names, FIM events of type 'deleted' and 'added'
                 should be generated. For this purpose, the test will create the directory and testing files
                 to be monitored and verify that they have been created correctly. It will then verify two cases,
                 on the one hand that the proper FIM events are generated when the testing files are renamed
                 in the monitored directory, and on the other hand, that these events are generated
                 when the monitored directory itself is renamed.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - rename target folder o file
            - Check that events are generated as expected.
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
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders:
            type: fixture
            brief: Create a given list of folders when the test starts. Delete the folders at the end of the test.
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
        - Verify that FIM events of type 'added' and 'deleted' are generated
          when monitored directories or files are renamed.

    input_description: The file 'configuration_basic_usage.yaml' provides the configuration
                       template.
                       The file 'cases_basic_usage_rename.yaml' provides the tes cases configuration details for each
                       test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'deleted' events)

    tags:
        - scheduled
        - whodata
        - realtime
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    def expect_events(path):
        event = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                        error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
        try:
            print("PATH: ", path)
            print("EVENT: ", str(event))
            assert 'added' in event['data']['type'] and path in event['data']['path'], \
                f'Deleted event not detected'
        except AssertionError:
            if 'deleted' not in event['data']['type'] and new_name not in event['data']['path']:
                raise AssertionError(f'Wrong event when renaming a non empty directory')

    mode = metadata['fim_mode']
    folder = test_folders[metadata['folder_id']]
    change_file_name = metadata['change_file_name']

    create_file(REGULAR, folder, old_name, content='')
    event = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                    error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
    validate_event(event, mode=mode)

    # testdir1 will have renamed files within.
    if folder == change_file_name:
        # Change the file name
        print("FOLDERS IN PATH " + str(os.listdir(folder)))
        print("FOLDER OLD NAME " + str(os.path.join(folder, old_name)))
        print("FOLDER NEW NAME " + os.path.join(os.path.join(folder, new_name)))
        rename_file(os.path.join(folder, old_name), os.path.join(folder, new_name))
        # Expect deleted and created events
        deleted = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                          error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
        try:
            assert 'deleted' in deleted['data']['type'] and os.path.join(folder, old_name) in deleted['data']['path']
        except AssertionError:
            if 'added' not in deleted['data']['type'] and os.path.join(folder, old_name) not in deleted['data']['path']:
                raise AssertionError(f'Wrong event when renaming a file')
        validate_event(deleted, mode=mode)

        added = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                        error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
        try:
            assert 'added' in added['data']['type'] and os.path.join(folder, new_name) in added['data']['path']
        except AssertionError:
            if 'deleted' not in added['data']['type'] and os.path.join(folder, new_name) not in added['data']['path']:
                raise AssertionError(f'Wrong event when renaming a file')
        validate_event(added, mode=mode)
    
    else:
        print("FOLDERS IN PATH " + str(os.listdir(folder)))
        print("FOLDER OLD NAME " + str(folder))
        print("FOLDER NEW NAME " + os.path.join(os.path.dirname(folder), new_name))
        rename_file(folder, os.path.join(os.path.dirname(folder), new_name))
        expect_events(new_name)
        expect_events(folder)
