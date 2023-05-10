'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM does not trigger
       events for existing files when a 'symbolic link' is changed to a non-empty directory.
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
from wazuh_testing import T_10, T_20, logger, LOG_FILE_PATH, REGULAR, SYMLINK
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (ERR_MSG_FIM_EVENT_NOT_RECIEVED, detect_audit_rules_reloaded,
                                                     callback_detect_event)
from test_fim.test_files.test_follow_symbolic_link.common import (wait_for_symlink_check, symlink_interval,
                                                                  modify_symlink)
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables

test_folders = [os.path.join(PREFIX, 'testdir'), os.path.join(PREFIX, 'testdir_target')]
testdir = test_folders[0]
testdir_link = os.path.join(PREFIX, 'testdir_link')
testdir_target = test_folders[1]
local_internal_options['syscheck.symlink_scan_interval'] = symlink_interval

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_symlink_and_dir.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_symlink_and_dir.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


# Fixtures
@pytest.fixture()
def prepare_symlinks():
    """Create files and symlinks"""
    create_file(REGULAR, testdir_target, 'regular1')
    create_file(SYMLINK, PREFIX, 'testdir_link', target=testdir)

    yield

    os.remove(testdir_link)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_symlink_dir_inside_monitored_dir(configuration, metadata, test_folders, create_monitored_folders, 
                                          prepare_symlinks, set_wazuh_configuration,
                                          configure_local_internal_options_function, restart_syscheck_function,
                                          wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events from existing files in a new target
                 of a monitored symlink. For this purpose, the test will create a 'symbolic link' to a
                 file/directory. Then, it will change the target to a non-empty directory, checking that
                 no FIM events are triggered for the files already in the directory. Finally, the test
                 will make file operatons and verify that FIM events are generated.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Create files and symlink
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Change symlink target to non-empty directory.
            - Check no events are generated for the files already in the directory.
            - Create a new file and validate the event is generated correctly.
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
        - Verify that no FIM events are generated for existing files when a 'symbolic link'
          is changed to a non-empty directory.

    input_description: The file 'configuration_symlink_and_dir.yaml' provides the configuration
                       template.
                       The file 'cases_symlink_and_dir.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)

    tags:
        - scheduled
        - time_travel
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    whodata = metadata['fim_mode'] == 'whodata'

    # Modify the symbolic link and expect no events
    modify_symlink(testdir_target, testdir_link)

    # Wait for both audit and the symlink check to run
    wait_for_symlink_check(wazuh_log_monitor)
    detect_audit_rules_reloaded(whodata, wazuh_log_monitor)

    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Create a file in the pointed folder and expect events
    create_file(REGULAR, testdir_link, 'regular2')

    wazuh_log_monitor.start(timeout=T_20, callback=callback_detect_event,
                            error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED)
