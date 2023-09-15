'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files are
       added, modified or deleted. It can monitor using Audit information (whodata mode). Whodata mode has an option
       'queue_size' that will save whodata events up until it is full so it can decode them and generate alerts. Events
       in excess of the queue will be dropped and handled in the next scheduled scan. This is done to avoid blocking
       the audit socket. Events in the queue are processed and removed from the queue, at a rate set my the max_eps tag.
       This tests aim to test the behavior of the queue in conjunction with max_eps, that fill/overflow the queue, then
       waiting for events to be processed and inserting files again, to verify files are processed in expected modes.

components:
    - fim

suite: audit_buffer

targets:
    - agent

daemons:
    - wazuh-syscheckd

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
import time

import pytest
from wazuh_testing import LOG_FILE_PATH, REGULAR, T_60, T_20
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import create_file
from wazuh_testing.modules.fim import TEST_DIR_1
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (callback_detect_file_added_event,  detect_audit_queue_full,
                                                     get_messages)


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables
test_folders = [os.path.join(PREFIX, TEST_DIR_1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_templates')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')


# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_audit_buffer_over_time.yaml')
t1_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_audit_buffer_over_time_no_overflow.yaml')
t2_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_audit_buffer_over_time_overflow.yaml')

# Test configurations
t1_configuration_parameters, t1_configuration_metadata, t1_test_case_ids = get_test_cases_data(t1_test_cases_path)
for count, value in enumerate(t1_configuration_parameters):
    t1_configuration_parameters[count]['TEST_DIRECTORIES'] = test_folders[0]
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# Test configurations
t2_configuration_parameters, t2_configuration_metadata, t2_test_case_ids = get_test_cases_data(t2_test_cases_path)
for count, value in enumerate(t2_configuration_parameters):
    t2_configuration_parameters[count]['TEST_DIRECTORIES'] = test_folders[0]
t2_configurations = load_configuration_template(configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata),
                         ids=t1_test_case_ids)
def test_audit_buffer_over_time_no_overflow(configuration, metadata, test_folders, set_wazuh_configuration,
                                            create_monitored_folders, configure_local_internal_options_function,
                                            restart_syscheck_function, wait_syscheck_start):
    '''
    description: This test validates the behavior of "queue_size" in tandem with "max_eps". Check that when files are
                 added equal to the whodata "queue_size" the queue does not overflow, after some files are processed
                 adding new files that do not exceed the empty space in the queue, all files are detected in whodata
                 mode.
    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Insert enough files to fill queue
            - Wait x seconds for space to be freed in queue
            - Insert enough files to fill queue again
            - Validate queue was full
            - Validate no event was dropped and all events were detected in whodata mode
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.5.0

    tier: 2

    parameters:
        - configuration:
            type: dict
            brief: Configuration values to apply to wazuh.
        - metadata:
            type: dict
            brief: Test case data.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the log files.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting FIM scan is detected.

    assertions:
        - Verify whadata queue is full
        - Verify all inserted files are detected in whodata mode if files are inserted after queue space is freed

    input_description: The file 'configuration_audit_buffer_over_time.yaml' provides the configuration
                       template.
                       The file 'cases_audit_buffer_over_time_no_overflow.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r".*(Internal audit queue is full). Some events may be lost. Next scheduled scan will recover lost data."
        - r".*Sending FIM event: (.+)$"
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    whodata_events = metadata['files_first_insert'] + metadata['files_second_insert']

    # Wait for FIM to process all initial whodata messages
    time.sleep(2)

    # Insert an amount of files
    for file in range(0, metadata['files_first_insert']):
        create_file(REGULAR, test_folders[0], f'test_file_{file}', content='')

    # Wait for files to be processed
    time.sleep(metadata['wait_time'])

    # Insert a second amount of files
    for file in range(0, metadata['files_second_insert']):
        create_file(REGULAR, test_folders[0], f'test_file_second_insert_{file}', content='')

    # Detect audit queue is full
    with pytest.raises(TimeoutError):
        detect_audit_queue_full(wazuh_log_monitor, update_position=False)

    # Get all file events
    results = wazuh_log_monitor.start(timeout=T_60, callback=callback_detect_file_added_event,
                                      accum_results=whodata_events,
                                      error_message=f"Did not receive the expected amount of \
                                                      whodata file added events").result()
    # Validate all files where found in whodata mode - no files where dropped
    for result in results:
        assert result['data']['mode'] == 'whodata', f"Expected whodata event, found {result['data']['mode']} event"


@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata),
                         ids=t2_test_case_ids)
def test_audit_buffer_overflow(configuration, metadata, test_folders, set_wazuh_configuration,
                               create_monitored_folders, configure_local_internal_options_function,
                               restart_syscheck_function, wait_syscheck_start):
    '''
    description: This test validates the behavior of "queue_size" in tandem with "max_eps". Check that when files are
                 added causing whodata queue to overflow, and after some files are processed, if new files are added
                 that do not exceed the empty space in the queue, only the files from the first insertion, that caused
                 the overflow are detected in scheduled mode. All files from second insertion are detected in whodata.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Insert enough files to fill queue
            - Detect if whodata queue has overflowed
            - Wait x seconds for space to be freed in queue
            - Insert files a second time
            - Validate only files from the first insert were detected in scheduled mode
            - Validate a all files from the second insert are detected.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.5.0

    tier: 2

    parameters:
        - configuration:
            type: dict
            brief: Configuration values to apply to wazuh.
        - metadata:
            type: dict
            brief: Test case data.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the log files.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting FIM scan is detected.

    assertions:
        - Verify when queue is full an event informs audit events may be lost
        - Verify when queue is full at start up audit healthcheck fails and does not start
        - Verify when using invalid values an error message is shown and does not start
        - Verify configured queue_size value
        - Verify real-time whodata thread is started correctly

    input_description: The file 'configuration_audit_buffer_over_time.yaml' provides the configuration template.
                       The file 'cases_audit_buffer_over_time_overflow.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r".*(Internal audit queue is full). Some events may be lost. Next scheduled scan will recover lost data."
        - r".*(Audit health check couldn't be completed correctly)."
        - fr".*Invalid value for element (\'{element}\': .*)"
        - r".*Internal audit queue size set to \'(.*)\'."
        - r'.*File integrity monitoring (real-time Whodata) engine started.*'
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    files_first_insert = metadata['files_first_insert']
    files_second_insert = metadata['files_second_insert']
    total_files = files_first_insert + files_second_insert

    # Wait for FIM to process all initial whodata messages
    time.sleep(2)

    # Insert an ammount of files
    for file in range(0, files_first_insert):
        create_file(REGULAR, test_folders[0], f'test_file_first_insert_{file}', content='')

    # Wait for files to be processed
    time.sleep(metadata["wait_time"])

    # Detect If queue_full message has been generated
    detect_audit_queue_full(wazuh_log_monitor, update_position=False)

    # Insert a second amount of files
    for file in range(0, files_second_insert):
        create_file(REGULAR, test_folders[0], f'test_file_second_insert_{file}', content='')

    # Get all file added events
    results = get_messages(callback_detect_file_added_event, timeout=T_20, max_events=total_files)

    second_set_events = 0
    for result in results:
        # Check that all of the files processed in scheduled mode where from the first batch only
        if result['data']['mode'] == 'scheduled':
            assert 'test_file_first_insert_' in result['data']['path'], "Expected only files from first set to be in\
                                                                         scheduled mode, found file from second set"
        # Count the events detected from second batch of files. Will only contain whodata because of previous assert
        if 'test_file_second_insert_' in result['data']['path']:
            second_set_events += 1

    # Check that all the files from the second insert have been detected
    assert second_set_events == files_second_insert, f"Unexpected amount of files detected from second insert, found: \
                                                       {second_set_events}, expected: {files_second_insert}"
