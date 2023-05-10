'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM stops monitoring the target of
       a 'symbolic_link' when the attribute 'follow_symbolic_link' is disabled.
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

from test_fim.test_files.test_follow_symbolic_link.common import testdir_target, testdir1, test_directories
from wazuh_testing import logger, T_10, LOG_FILE_PATH, REGULAR  
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.file import create_file, modify_file_content, delete_file
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
t1_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_symlink_disabled_file.yaml')
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_monitored_file.yaml')
t2_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_symlink_disabled_folder.yaml')
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_monitored_dir.yaml')

# Test configurations
t1_configuration_parameters, t1_configuration_metadata, t1_test_case_ids = get_test_cases_data(t1_test_cases_path)
for count, value in enumerate(t1_configuration_parameters):
    t1_configuration_parameters[count]['FOLLOW_MODE'] = 'no'
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata)

t2_configuration_parameters, t2_configuration_metadata, t2_test_case_ids = get_test_cases_data(t2_test_cases_path)
for count, value in enumerate(t2_configuration_parameters):
    t2_configuration_parameters[count]['FOLLOW_MODE'] = 'no'
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata)

configurations = t1_configurations + t2_configurations
configuration_metadata = t1_configuration_metadata + t2_configuration_metadata
test_case_ids = t1_test_case_ids + t2_test_case_ids


# Tests
@pytest.mark.parametrize('test_folders', [test_directories], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_follow_symbolic_disabled(configuration, metadata, test_folders, create_monitored_folders, 
                                          prepare_symlinks, set_wazuh_configuration,
                                          configure_local_internal_options_function, restart_syscheck_function,
                                          wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon considers a 'symbolic link' to be a regular file when
                 the attribute 'follow_symbolic_link' is set to 'no'. For this purpose, the test will monitor
                 a 'symbolic link' pointing to a file/directory. Once FIM starts, it will create and not expect
                 events inside the pointed folder. Then, the test will modify the link target and check that
                 no events are triggered. Finally, it will remove the link target and verify that no FIM events
                 have been generated.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - path:
            type: str
            brief: Path to the target file or directory.
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that no FIM events are generated when performing file operations on a 'symbolic link' target.

    input_description: Two test cases (monitored_file and monitored_dir) are contained in external YAML file
                       (wazuh_conf.yaml) which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, these are combined with the testing directories to be monitored defined in
                       the 'common.py' module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
        - whodata
        - realtime
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    regular_file = 'regular1'
    error_msg = 'A "Sending FIM event: ..." event has been detected. No events should be detected at this time.'
    main_folder = test_dirs[metadata['main_folder']]

    # If the symlink targets to a directory, create a file in it and ensure no event is raised.
    if metadata['symlink_target'] == {'monitored_dir'}:
        create_file(REGULAR, main_folder, regular_file)
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
            logger.error(error_msg)
            raise AttributeError(error_msg)

    # Modify the target file and don't expect any events
    modify_file_content(main_folder, regular_file, new_content='Modify sample')
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(error_msg)
        raise AttributeError(error_msg)

    # Delete the target file and don't expect any events
    delete_file(os.path.join(main_folder, regular_file))
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=T_10, callback=callback_detect_event)
        logger.error(error_msg)
        raise AttributeError(error_msg)
