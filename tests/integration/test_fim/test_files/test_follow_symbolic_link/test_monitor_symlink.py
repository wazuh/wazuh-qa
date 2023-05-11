'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM generates events when monitoring
       a 'symbolic link' that points to a file or a directory.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files for
       changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_follow_symbolic_link

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - macos
    - solaris

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_follow_symbolic_link
'''
import os
import pytest

from test_fim.test_files.test_follow_symbolic_link.common import delete_file_or_path, test_directories
from wazuh_testing import LOG_FILE_PATH, REGULAR, T_20
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.file import modify_file_content, create_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import callback_detect_event, ERR_MSG_FIM_EVENT_NOT_RECIEVED
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables
test_dirs = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir_target')]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_monitor_symlink_file.yaml')
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_monitored_file.yaml')
t2_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_monitor_symlink_folder.yaml')
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_monitored_dir.yaml')

# Test configurations
t1_configuration_parameters, t1_configuration_metadata, t1_test_case_ids = get_test_cases_data(t1_test_cases_path)
for count, value in enumerate(t1_configuration_parameters):
    t1_configuration_parameters[count]['FOLLOW_MODE'] = 'yes'
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata)

t2_configuration_parameters, t2_configuration_metadata, t2_test_case_ids = get_test_cases_data(t2_test_cases_path)
for count, value in enumerate(t2_configuration_parameters):
    t2_configuration_parameters[count]['FOLLOW_MODE'] = 'yes'
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata)

configurations = t1_configurations + t2_configurations
configuration_metadata = t1_configuration_metadata + t2_configuration_metadata
test_case_ids = t1_test_case_ids + t2_test_case_ids

# Tests
@pytest.mark.parametrize('test_folders', [test_directories], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_symlink_dir_inside_monitored_dir(configuration, metadata, test_folders, create_monitored_folders, 
                                          prepare_symlinks, set_wazuh_configuration,
                                          configure_local_internal_options_function, restart_syscheck_function,
                                          wait_syscheck_start):

    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when monitoring a symlink that points
                 to a file or a directory. For this purpose, the test will monitor a 'symbolic link' pointing
                 to a file/directory. Once FIM starts, if the link is a folder, creates a file and checks if
                 the expected FIM 'added' event is raised. Then, it will modify the link target and expect
                 the 'modified' event. Finally, the test will remove the link target and verify that
                 the FIM 'delete' event is generated.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Create files and symlink
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Create a file in folder if symlink is targeting a folder.
            - Modify and Delete file in symlink target.
            - Check events are generated correctly.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.2.0

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
        - prepare_symlinks:
            type: fixture
            brief: Prepare the symbolic link and the target directory.
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
        - Verify that FIM events are generated when performing file operations on a 'symbolic link' target.

    input_description: Two configuration files 'monitored_dir.yaml' and 'monitored_file.yaml' provide the 
                       configuration template.
                       Two files 'cases_monitor_symlink_file.yaml' and 'cases_monitor_symlink_folder.yaml' provide the
                       test cases configuration details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
        - realtime
        - whodata
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    main_folder = test_dirs[metadata['main_folder']]
    file1 = 'regular1'

    # Add creation if symlink is pointing to a folder
    if metadata['symlink_target'] == 'folder':
        create_file(REGULAR, main_folder, file1, content='')
        add = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event).result()
        assert 'added' in add['data']['type'] and file1 in add['data']['path'], \
            "'added' event not matching"

    # Modify the linked file and expect an event
    modify_file_content(main_folder, file1, 'Sample modification')
    modify = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                     error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        "'modified' event not matching"

    # Delete the linked file and expect an event
    delete_file_or_path(main_folder, file1)
    delete = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                     error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
    assert 'deleted' in delete['data']['type'] and file1 in delete['data']['path'], \
        "'deleted' event not matching"
