'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files are
       added, modified or deleted. It can monitor using Audit information (whodata mode). Whodata mode has an option
       'queue_size' that will save whodata events up until it is full so it can decode them and generate alerts. Events
       in excess of the queue will be dropped and handled in the next scheduled scan. This is done to avoid blocking
       the audit socket. This tests aim to test the behavior of the queue, by inserting files above or below the set
       value for queue_size, and verify if events were detected in whodata or scheduled mode appropiately.

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


import pytest
from wazuh_testing import LOG_FILE_PATH, REGULAR, T_10, T_20
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import create_file
from wazuh_testing.modules.fim import TEST_DIR_1
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (callback_detect_file_added_event,  detect_audit_queue_full,
                                                     detect_initial_scan_start, get_messages)


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables
test_folders = [os.path.join(PREFIX, TEST_DIR_1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')


# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_audit_buffer_behavior.yaml')
t1_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_audit_buffer_no_overflow.yaml')
t2_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_audit_buffer_overflown.yaml')

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
def test_audit_buffer_no_overflow(configuration, metadata, test_folders, set_wazuh_configuration,
                                  create_monitored_folders, configure_local_internal_options_function,
                                  restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check that when files are added equal to the whodata "queue_size", the queue does not overflow, all
                 files are detected in whodata mode, and after the next scan no file is detected in scheduled mode.


    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Insert a given amount of files
            - Check that no "queue full" message is detected (Queue has not overflown)
            - Validate real-time whodata thread is started correctly
            - On invalid values, validate error and that whodata does not start.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.5.0

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
        - Verify the queue does not overflow after inserting files
        - Verify all files are detected in whodata mode

    input_description: The file 'configuration_audit_buffer_values' provides the configuration template.
                       The file 'cases_audit_buffer_values.yaml' provides the test cases details for each test case.

    expected_output:
        - r".*(Internal audit queue is full). Some events may be lost. Next scheduled scan will recover lost data."
        - r".*Sending FIM event: (.+)$"
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    files_to_add = metadata['files_to_add']
    whodata_events = files_to_add

    # Insert an ammount of files
    for file in range(0, files_to_add):
        create_file(REGULAR, test_folders[0], f'test_file_{file}', content='')

    # Check that queue has not been overflown
    with pytest.raises(TimeoutError):
        detect_audit_queue_full(wazuh_log_monitor, update_position=False)

    # Get all file events
    results = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_file_added_event,
                                      accum_results=whodata_events,
                                      error_message=f"Did not receive the expected {whodata_events} amount of \
                                                      whodata file added events").result()
    # Check all files are detected in whodata mode
    for result in results:
        assert result['data']['mode'] == 'whodata', f"Expected whodata event, found {result['data']['mode']} event"

    # Detect next scheduled scan
    detect_initial_scan_start(wazuh_log_monitor, timeout=T_10)

    # Check no events are found after scan.
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_file_added_event,
                                accum_results=1, error_message="Found unexpected file added event \
                                                                in during scheduled scan")


@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata),
                         ids=t2_test_case_ids)
def test_audit_buffer_overflown(configuration, metadata, test_folders, set_wazuh_configuration,
                                create_monitored_folders_module, configure_local_internal_options_function,
                                restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check that when files are exceeding the whodata "queue_size" value the queue overflows, and the
                 excess files files are detected in scheduled mode, and after the next scheduled scan.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Insert a given number of files
            - Check that the "queue_full" event appears
            - Check the amount of files that were detected prior to the queue being full
            - Check the excess files are detected in scheduled mode after the following scan
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.5.0

    tier: 2

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
        - Verify when queue is full an event informs audit events may be lost
        - Verify that files detected in whodata mode before it being full are equal or more than the configured value
        - Verify the excess files inserted after queue full are detected in scheduled mode.

    input_description: The file 'configuration_audit_buffer_values' provides the configuration template.
                       The file 'cases_audit_buffer_values.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r".*(Internal audit queue is full). Some events may be lost. Next scheduled scan will recover lost data."
        - r".*Sending FIM event: (.+)$"
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    files_to_add = metadata['files_to_add']

    # Insert an ammount of files
    for file in range(0, files_to_add):
        create_file(REGULAR, test_folders[0], f'test_file_{file}', content='')

    # Detect If queue_full message has been generated
    detect_audit_queue_full(wazuh_log_monitor, update_position=False)

    # Get all file added events
    results = get_messages(callback_detect_file_added_event, timeout=T_10,
                           error_message=f"Did not receive the expected file added events")

    # Check the ammount of added events in whodata mode is equal or more than the expected value
    found_whodata_events = 0
    for result in results:
        if result['data']['mode'] == 'whodata':
            found_whodata_events = found_whodata_events + 1
    assert found_whodata_events >= metadata['whodata_events'], f"Found less whodata File added events \
                                                                 than the expected {metadata['whodata_events']}"

    # Wait for scheduled scan so the rest of file events are generated
    detect_initial_scan_start(wazuh_log_monitor, timeout=T_10)

    # Get all file added events
    results = get_messages(callback_detect_file_added_event, timeout=T_10,
                           error_message=f"Did not receive the expected file added events")

    # Check the amount of added events in scheduled mode is equal to the amount of files created
    # minus the generated whodata events
    scheduled_events = files_to_add - found_whodata_events
    found_scheduled_events = 0
    for result in results:
        if result['data']['mode'] == 'scheduled':
            found_scheduled_events += 1

    assert found_scheduled_events == scheduled_events, f"Wrong amount of scheduled events found. Found \
                                                             {found_scheduled_events}, Expected {scheduled_events}"
