'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if, after manipulating files while
       the FIM database is in 'full database alert' mode, files that are deleted in 'normal' mode
       generate events consistent with deleted files.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_file_limit

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-limit

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_file_limit
'''
import os
from time import sleep

import pytest
from wazuh_testing import T_10, T_20
from wazuh_testing.fim import LOG_FILE_PATH, delete_file, generate_params, create_file, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import create_file, delete_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (callback_detect_event, ERR_MSG_DATABASE_FULL_ALERT_EVENT,
                                                     CB_FILE_LIMIT_CAPACITY, ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL,
                                                     ERR_MSG_NO_EVENTS_EXPECTED, ERR_MSG_DELETED_EVENT_NOT_RECIEVED)
from wazuh_testing.modules.fim.utils import generate_params

# Marks
pytestmark = [pytest.mark.tier(level=1)]

# Variables
base_file_name = "test_file"
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_delete_full.yaml')
testdir1 = test_directories[0]
NUM_FILES = 7
NUM_FILES_TO_CREATE = 8
sleep_time = 2

# Configurations

file_limit_list = ['10']
conf_params = {'TEST_DIRECTORIES': testdir1, 'LIMIT': str(NUM_FILES)}

params, metadata = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions


def extra_configuration_before_yield():
    """Generate files to fill database"""

    create_file(REGULAR, testdir1, f'{base_file_name}{10}')
    for i in range(2, NUM_FILES_TO_CREATE):
        create_file(REGULAR, testdir1, f'{base_file_name}{i}', content='content')


# Tests


@pytest.mark.parametrize('folder, file_name', [(testdir1, f'{base_file_name}{1}')])
def test_file_limit_delete_full(folder, file_name, configure_local_internal_options_module, get_configuration,
                                configure_environment, restart_syscheckd):
    '''
    description: Check a specific case. If a testing file ('test_file1') is not inserted in the FIM database
                 (because the maximum number of files to be monitored has already been reached), and another
                 testing file ended in 0 ('test_file10') is in the database, after deleting 'test_file1',
                 the FIM event 'delete' was raised for the 'test_file10' file. For this purpose, the test
                 will monitor a directory and create several test files until the maximum limit of monitored
                 files is reached. Then, it will create and delete the file 'test_file1' and wait for
                 no FIM events to be generated (file limit reached). Finally, it will delete 'test_file10'
                 and verify that the 'deleted' FIM event matches that file.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - folder:
            type: str
            brief: Path to the directory to be monitored.
        - file_name:
            type: str
            brief: Name of the testing file to be created.
        - configure_local_internal_options_module:
            type: fixture
            brief: Set the local_internal_options for the test.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the Wazuh logs file and start a new monitor.

    assertions:
        - Verify that the FIM database is in 'full database alert' mode
          when the maximum number of files to monitor has been reached.
        - Verify that no FIM events are generated when operations are performed on new files
          and the limit of files to monitor has been reached.
        - Verify that after manipulating files in 'full database alert' mode, files that are deleted
          while the FIM database is in 'normal' mode generate events consistent with deleted files.

    input_description: A test case (tags_delete_full) is contained in external YAML file (wazuh_conf_delete_full.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is combined with
                       the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*File database is (\\d+)% full'
        - r'.*Sending FIM event: (.+)$' ('deleted' event)

    tags:
        - realtime
        - who_data
    '''
    #Check that database is full and assert database usage percentage is 100%
    database_state = wazuh_log_monitor.start(timeout=T_20,
                                             callback=generate_monitoring_callback(CB_FILE_LIMIT_CAPACITY),
                                             error_message=ERR_MSG_DATABASE_FULL_ALERT_EVENT).result()

    assert database_state == '100', ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL

    # Create a file with the database being full - Should not generate events
    create_file(REGULAR, testdir1, file_name)
    sleep(sleep_time)
    # Delete the file created - Should not generate events
    delete_file(os.path.join(folder, file_name))

    # Check no Creation or Deleted event has been  generated
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=T_10,
                                        callback=callback_detect_event).result()
        assert event is None, ERR_MSG_NO_EVENTS_EXPECTED

    # Delete the first file that was created (It is included in DB)
    delete_file(os.path.join(folder, f'{file_name}{0}'))

    #Get that the file deleted generetes an event and assert the event data path.
    event = wazuh_log_monitor.start(timeout=T_20,
                                    callback=callback_detect_event,
                                    error_message=ERR_MSG_DELETED_EVENT_NOT_RECIEVED).result()

    assert event['data']['path'] == os.path.join(folder, f'{file_name}{0}')
