'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM manages
       the 'inotify watches' (adds, deletes) when a monitored directory is modified.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

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
from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, regular_file_cud, generate_params, detect_initial_scan,
                               callback_delete_watch, callback_realtime_added_directory,
                               callback_num_inotify_watches)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables and configuration

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_num_watches.yaml')

testdir = os.path.join(PREFIX, 'testdir')
test_directories = [testdir]

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir}, modes=['realtime'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

if sys.platform == 'win32':
    EXPECTED_WATCHES = 1
else:
    EXPECTED_WATCHES = 3


# Functions


def extra_configuration_after_yield():
    """Make sure to delete the directory after performing the test"""
    sh.rmtree(os.path.join(PREFIX, 'changed_name'), ignore_errors=True)


# Fixtures


@pytest.fixture(scope='function')
def restart_syscheckd_each_time(request):
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    if not os.path.exists(testdir):
        os.mkdir(testdir)

    control_service('start', daemon='wazuh-syscheckd')
    detect_initial_scan(file_monitor)


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('removed, renamed', [
    (True, False),
    (False, True)
])
def test_readded_watches(removed, renamed, get_configuration, configure_environment, restart_syscheckd_each_time):
    '''
    description: Check if the 'wazuh-syscheckd' daemon deletes an 'inotify watch' when renaming or deleting
                 a monitored directory, and add an 'inotify watch' when the directory is restored. For this
                 purpose, the test will create and monitor a testing directory. Once FIM is started, it will
                 verify that a watch has been added. Then, the test will make file operations (rename, delete)
                 on the monitored directory and check if the watch has been removed. Finally, it will restore
                 the directory and verify that the 'inotify watch' has been added by checking the FIM events.

    wazuh_min_version: 4.2.0

    parameters:
        - removed:
            type: bool
            brief: True if the directory must be removed. False otherwise.
        - renamed:
            type: bool
            brief: True if the directory must be renamed. False otherwise.
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
        - Verify that FIM removes 'inotify watches' when deleting or renaming a monitored folder.
        - Verify that FIM adds 'inotify watches' when a deleted monitored folder is restored.

    input_description: A test case is contained in external YAML file (wazuh_conf_num_watches.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Folders monitored with real-time engine'
        - r'.*Directory added for real time monitoring' (On Windows systems)
        - r'.*Realtime watch deleted for'

    tags:
        - realtime
    '''
    # Check Wazuh add directory to realtime mode
    if sys.platform == 'win32':
        directory = wazuh_log_monitor.start(timeout=40, callback=callback_realtime_added_directory,
                                            error_message='Did not receive expected '
                                                          '"Directory added for real time monitoring: ..." event'
                                            ).result()
        assert (directory == testdir), 'Unexpected path'

    # Remove/Rename folder and check Wazuh delete waches
    if removed:
        sh.rmtree(testdir, ignore_errors=True)
    elif renamed:
        os.rename(testdir, os.path.join(PREFIX, 'changed_name'))

    directory = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_delete_watch,
                                        error_message='Did not receive expected "Delete watch ..." event').result()
    assert (directory == testdir), 'Unexpected path'

    # Create directories again and check Wazuh add watches
    os.mkdir(testdir)

    num_watches = wazuh_log_monitor.start(timeout=40, callback=callback_num_inotify_watches,
                                          error_message='Did not receive expected '
                                                        '"Folders monitored with real-time engine: ..." event'
                                          ).result()

    assert (num_watches and num_watches != EXPECTED_WATCHES), 'Watches not added'
    regular_file_cud(testdir, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, triggers_event=True)
