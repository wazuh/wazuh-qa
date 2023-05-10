'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM monitors the target
       of a 'symbolic link' when it is changed and when that change is reverted.
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

from test_fim.test_files.test_follow_symbolic_link.common import (testdir1, modify_symlink, testdir_link, 
                                                                  wait_for_symlink_check, test_directories)
from wazuh_testing import logger, T_10, LOG_FILE_PATH
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.file import modify_file_content
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import detect_audit_rules_reloaded, callback_detect_event
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_revert_symlink.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_monitored_file.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['FOLLOW_MODE'] = 'yes'
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Tests
@pytest.mark.parametrize('test_folders', [test_directories], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_symlink_dir_inside_monitored_dir(configuration, metadata, test_folders, create_monitored_folders, 
                                          set_wazuh_configuration, configure_local_internal_options_function, 
                                          prepare_symlinks, restart_syscheck_function, wait_syscheck_start):

    '''
    description: Check if the 'wazuh-syscheckd' daemon detects new targets when monitoring a directory with
                 a symlink and its target is changed. For this purpose, the test will create a 'symbolic link'
                 to a file/directory. Then, it will change the target to a directory and create some files
                 inside, expecting all the FIM events. After the events are processed, the test will change
                 the link to its previous target, and finally, it will make file operations and expect FIM events.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Create files and symlink
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Change symlink target to empty directory.
            - Create files and check events are generated.
            - Revert the symlink target to original target.
            - Modify file and validate events are generated.
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
        - Verify that FIM events are generated when a monitored 'symbolic link' target
          is changed to a new directory.
        - Verify that FIM events are generated when a monitored 'symbolic link' target
          is reverted to the previous directory.


    input_description: The file 'configuration_monitored_file.yaml' provides the configuration
                       template.
                       The file 'cases_revert_symlink.yaml' provides the tes cases configuration
                       details for each test case.


    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - whodata
        - realtime
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    def modify_and_assert(file):
        modify_file_content(testdir1, file, new_content='Sample modification')
        ev = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event).result()
        assert 'modified' in ev['data']['type'] and os.path.join(testdir1, file) in ev['data']['path'], \
            f"'modified' event not matching for {testdir1} {file}"

    whodata = metadata['fim_mode'] == 'whodata'
    file1 = 'regular1'
    file2 = 'regular2'

    # Don't expect an event since it is not being monitored yet
    modify_file_content(testdir1, file2, new_content='Sample modification')
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Change the target to the folder and now expect an event
    modify_symlink(testdir1, os.path.join(testdir_link, 'symlink'))
    wait_for_symlink_check(wazuh_log_monitor)
    detect_audit_rules_reloaded(whodata, wazuh_log_monitor)
    modify_and_assert(file2)

    # Modify symlink target, wait for sym_check to update it
    modify_symlink(os.path.join(testdir1, file1), os.path.join(testdir_link, 'symlink'))
    wait_for_symlink_check(wazuh_log_monitor)
    # Wait for audit to reload the rules
    detect_audit_rules_reloaded(whodata, wazuh_log_monitor)

    modify_file_content(testdir1, file2, new_content='Sample modification2')
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
    modify_and_assert(file1)
