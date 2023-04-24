'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM detects
       the correct 'inotify watches' number when renaming and deleting a monitored directory.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_inotify

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
    - fim_inotify
'''
import os
import shutil as sh
import sys

import pytest
from wazuh_testing import T_60
from wazuh_testing.fim import LOG_FILE_PATH, callback_num_inotify_watches, generate_params, detect_initial_scan
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir1', 'sub1'),
                    os.path.join(PREFIX, 'testdir1', 'sub2')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_num_watches.yaml')
testdir1 = test_directories[0]
NO_WATCHES = 0
EXPECTED_WATCHES = 3

if sys.platform == 'win32':
    EXPECTED_WATCHES = 1

# Configurations

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1}, modes=['realtime'])

configurations1 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1}, modes=['scheduled'])

configurations2 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

configurations = configurations1 + configurations2


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def restart_syscheckd_each_time(request):
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    if not os.path.exists(testdir1):
        for directory in test_directories:
            os.mkdir(directory)

    control_service('start', daemon='wazuh-syscheckd')
    detect_initial_scan(file_monitor)


# Functions


def extra_configuration_after_yield():
    """Make sure to delete the directory after performing the test"""
    sh.rmtree(os.path.join(PREFIX, 'changed_name'), ignore_errors=True)


# Tests


@pytest.mark.parametrize('realtime_enabled, decreases_num_watches, rename_folder', [
    (True, True, False),
    (True, True, True),
    (True, False, False),
    (False, False, False)
])
def test_num_watches(realtime_enabled, decreases_num_watches, rename_folder, get_configuration, configure_environment,
                     restart_syscheckd_each_time):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the correct number of 'inotify watches' when
                 renaming and deleting a monitored directory. For this purpose, the test will create and monitor
                 a folder with two subdirectories. Once FIM is started, it will verify that three watches have
                 been detected. If these 'inotify watches' are correct, the test will make file operations on
                 the monitored folder or do nothing. Finally, it will verify that the 'inotify watches' number
                 detected in the generated FIM events is correct.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - realtime_enabled:
            type: bool
            brief: True if 'realtime' monitoring mode is enabled. False otherwise.
        - decreases_num_watches:
            type: bool
            brief: True if the 'inotify watches' number must decrease. False otherwise.
        - rename_folder:
            type: bool
            brief: True if the testing folder must be renamed. False otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd_each_time:
            type: fixture
            brief: Clear the 'ossec.log' file, add a testing directory, and start a new monitor in each test case.

    assertions:
        - Verify that FIM detects that the 'inotify watches' number is correct
          before and after modifying the monitored folder.
        - Verify that FIM adds 'inotify watches' when monitored directories have been removed or renamed, and
          they are restored.

    input_description: A test case (num_watches_conf) is contained in external YAML file (wazuh_conf_num_watches.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Folders monitored with real-time engine'

    tags:
        - realtime
        - scheduled
    '''
    check_apply_test({'num_watches_conf'}, get_configuration['tags'])

    if ((get_configuration['metadata']['fim_mode'] == "scheduled" and realtime_enabled) or
            (get_configuration['metadata']['fim_mode'] == "realtime" and not realtime_enabled)):
        pytest.skip("Does not apply to this config file")

    # Check that the number of inotify watches is correct before modifying the folder
    try:
        num_watches = wazuh_log_monitor.start(timeout=T_60, callback=callback_num_inotify_watches,
                                              error_message='Did not receive expected '
                                                            '"Folders monitored with real-time engine: ..." event'
                                              ).result()
    except TimeoutError:
        if not realtime_enabled:
            pass
        else:
            pytest.fail('Did not receive expected "Folders monitored with real-time engine: ..." event')
    else:
        if not realtime_enabled:
            pytest.fail('Received unexpected the "Folders monitored with real-time engine: ..."'
                        'event in scheduled mode')

        if num_watches:
            if decreases_num_watches and not rename_folder:  # Delete folder
                assert num_watches == str(EXPECTED_WATCHES), 'Wrong number of inotify watches before deleting folder'
            elif decreases_num_watches and rename_folder:  # Rename folder
                assert num_watches == str(EXPECTED_WATCHES), 'Wrong number of inotify watches before renaming folder'
            elif not decreases_num_watches and not rename_folder:  # Not modifying the folder
                error_msg = 'Wrong number of inotify watches when not modifying the folder'
                assert num_watches == str(EXPECTED_WATCHES), error_msg
        else:
            pytest.fail('Wrong number of inotify watches')

    if realtime_enabled:
        if decreases_num_watches and not rename_folder:
            sh.rmtree(testdir1, ignore_errors=True)
        elif decreases_num_watches and rename_folder:
            os.rename(testdir1, os.path.join(PREFIX, 'changed_name'))

    try:
        # Check that the number of inotify watches is correct after modifying the folder
        num_watches = wazuh_log_monitor.start(timeout=T_60, callback=callback_num_inotify_watches,
                                              error_message='Did not receive expected '
                                                            '"Folders monitored with real-time engine: ..." event'
                                              ).result()
    except TimeoutError:
        if not realtime_enabled:
            pass
        else:
            pytest.fail('Did not receive expected "Folders monitored with real-time engine: ..." event')
    else:
        if not realtime_enabled:
            pytest.fail('Received unexpected the "Folders monitored with real-time engine: ..."'
                        'event in scheduled mode')

        if num_watches:
            if decreases_num_watches and not rename_folder:  # Delete folder
                assert num_watches == str(NO_WATCHES), 'Wrong number of inotify watches after deleting folder'
            elif decreases_num_watches and rename_folder:  # Rename folder
                assert num_watches == str(NO_WATCHES), 'Wrong number of inotify watches after renaming folder'
            elif not decreases_num_watches and not rename_folder:  # Not modifying the folder
                error_msg = 'Wrong number of inotify watches when not modifying the folder'
                assert num_watches == str(EXPECTED_WATCHES), error_msg
        else:
            pytest.fail('Wrong number of inotify watches')

    # If directories have been removed or renamed, create directories again and check Wazuh add watches
    if decreases_num_watches:
        for directory in test_directories:
            os.mkdir(directory)

        num_watches = wazuh_log_monitor.start(timeout=T_60, callback=callback_num_inotify_watches,
                                              error_message='Did not receive expected '
                                                            '"Folders monitored with real-time engine: ..." event'
                                              ).result()

        assert (num_watches and num_watches != EXPECTED_WATCHES), 'Watches not added'
