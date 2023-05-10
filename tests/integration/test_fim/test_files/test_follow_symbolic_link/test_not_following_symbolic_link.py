'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM stops monitoring
       the target of a 'symbolic_link' found in the monitored directory when the attribute
       'follow_symbolic_link' is disabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

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


from test_fim.test_files.test_follow_symbolic_link.common import modify_symlink
from wazuh_testing import T_10, T_20, logger, LOG_FILE_PATH, REGULAR, SYMLINK
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.file import create_file, modify_file_content, delete_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import callback_detect_event, ERR_MSG_FIM_EVENT_NOT_RECIEVED


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir_link'), os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2')]
testdir_link, testdir1, testdir2 = test_directories


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_not_following_symbolic_link.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_non_monitored_dir.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Tests
@pytest.mark.parametrize('test_folders', [test_directories], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_symbolic_monitor_directory_with_symlink(configuration, metadata, test_folders, create_monitored_folders, 
                                                 set_wazuh_configuration, configure_local_internal_options_function,
                                                 restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when monitoring a directory with a symlink and
                 not the symlink itself. For this purpose, the test will create some files in a non-monitored folder
                 and will not expect any events. Then, it will create a 'symbolic link' inside the monitored folder
                 pointing to the non-monitored folder. The test will expect an FIM 'added' event with the path
                 of the 'symbolic link', as it is within a monitored directory. It will create some events in
                 the link target and will not expect any events. Finally, the test will change the link target,
                 and it will expect an FIM 'modified' event.

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
        - Verify that no FIM events are generated when performing file operations
          on a 'symbolic link' target in a monitored directory.
        - Verify that FIM events are generated when adding or modifying the 'symbolic link' itself.

    input_description: The file 'configuration_non_monitored_file.yaml' provides the configuration
                       template.
                       The file 'cases_not_following_symbolic_link.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    monitored_dir = testdir_link
    non_monitored_dir1 = testdir1
    non_monitored_dir2 = testdir2
    sym_target = metadata['sym_target']
    
    filename1 = f'{sym_target}regular1'
    filename2 = f'{sym_target}regular2'
    symlink_name = f'{sym_target}symlink'
    a_path = os.path.join(non_monitored_dir1, filename1)
    # Future target of symlink. Will be a file or a folder according to de sym_target variable
    b_path = os.path.join(non_monitored_dir1, filename2) if sym_target == 'file' else non_monitored_dir2
    symlink_path = os.path.join(monitored_dir, symlink_name)

    # Create regular files out of the monitored directory and don't expect its event
    create_file(REGULAR, non_monitored_dir1, filename1, content='')
    create_file(REGULAR, non_monitored_dir1, filename2, content='')

    # Create the symlink and expect its event, since it's withing the monitored directory
    target = a_path if sym_target == 'file' else non_monitored_dir1
    create_file(SYMLINK, monitored_dir, symlink_name, target=target)
    wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                            error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED)

    # Modify the target file and don't expect any event
    modify_file_content(non_monitored_dir1, filename1, new_content='Modify sample')
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Modify the target of the symlink and expect the modify event
    modify_symlink(target=b_path, path=symlink_path)
    result = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                     error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
    if 'modified' in result['data']['type']:
        logger.info("Received modified event. No more events will be expected.")
    elif 'deleted' in result['data']['type']:
        logger.info("Received deleted event. Now an added event will be expected.")
        result = wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                                         error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED).result()
        assert 'added' in result['data']['type'], f"The event {result} should be of type 'added'"
    else:
        assert False, f"Detected event {result} should be of type 'modified' or 'deleted'"

    # Remove and restore the target file. Don't expect any events
    delete_file(os.path.join(b_path, filename2))
    create_file(REGULAR, non_monitored_dir1, filename2, content='')
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
