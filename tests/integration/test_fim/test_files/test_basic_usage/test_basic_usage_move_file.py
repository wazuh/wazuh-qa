'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events are generated when files
       are moved between monitored directories.
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
import sys

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH, REGULAR
from wazuh_testing.fim import create_file, delete_file
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import callback_detect_event, ERR_MSG_FIM_EVENT_NOT_RECIEVED
from wazuh_testing.modules.fim.classes import validate_event
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options

# Marks

pytestmark = pytest.mark.tier(level=0)

# Cariables
test_folders = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                os.path.join(PREFIX, 'testdir1', 'subdir')]
directory_str = ','.join(test_folders)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_basic_usage_move_file.yaml')
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
def test_move_file(configuration, metadata, test_folders, set_wazuh_configuration, create_monitored_folders,
                   configure_local_internal_options_function, restart_syscheck_function,
                   wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'added' and 'deleted' events when moving a file
                 from a monitored folder to another one. For this purpose, the test will create a testing file and
                 move it from the source directory to the target directory. Then, it waits until
                 the next scheduled scan, and finally, it removes the testing file and verifies that
                 the expected FIM events have been generated.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Create files in monitored folders
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Move file from source directory to target directory.
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
        - Verify that FIM events of type 'added' and 'deleted' are generated when files are moved between monitored and
          unmonitored directories.

    input_description: The file 'configuration_basic_usage.yaml' provides the configuration
                       template.
                       The file 'cases_basic_usage_move_file.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', and 'deleted' events)'
    '''
    # Variables
    source_folder = test_folders[metadata['source_folder']]
    target_folder = PREFIX if metadata['target_folder'] == 'prefix' else test_folders[metadata['target_folder']]
    triggers_delete_event = metadata['triggers_delete_event']
    triggers_add_event = metadata['triggers_add_event']
    file_name ='regular_file'
    mode = metadata['fim_mode']
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


    # Create file inside folder
    create_file(REGULAR, source_folder, file_name, content='')

    if source_folder in test_folders:
        event = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                        error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
        validate_event(event, mode=mode)

    # Move file to target directory
    os.rename(os.path.join(source_folder, file_name), os.path.join(target_folder, file_name))

    # Monitor expected events
    events = wazuh_log_monitor.start(timeout=T_20,callback=callback_detect_event,
                                     accum_results=(triggers_add_event + triggers_delete_event),
                                     error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()

    # Expect deleted events
    if isinstance(events, list):
        events_data = [(event['data']['type'],
                        event['data']['path'],
                        os.path.join(source_folder, file_name) if event['data']['type'] == 'deleted' else os.path.join(
                            target_folder, file_name))
                       for event in events]
        assert set([event[0] for event in events_data]) == {'deleted', 'added'}
        for _, path, expected_path in events_data:
            assert path == expected_path
    else:
        if triggers_delete_event:
            assert 'deleted' in events['data']['type'] and os.path.join(source_folder, file_name) in events['data']['path']
        else:
            assert 'added' in events['data']['type'] and os.path.join(target_folder, file_name) in events['data']['path']

    events = [events] if not isinstance(events, list) else events
    for ev in events:
        validate_event(ev, mode=mode)

    # Remove file
    delete_file(target_folder, file_name)
    if target_folder in test_folders:
        event = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                        error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
        validate_event(event, mode=mode)
