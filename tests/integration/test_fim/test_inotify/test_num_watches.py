# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil as sh
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_num_inotify_watches, generate_params, detect_initial_scan
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file

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
    """
    Check if the number of inotify watches is correct when renaming and deleting a directory.

    It creates a folder with two subdirectories and checks that there are three watches. If the number is correct,
    deletes, renames or does nothing to the folder and checks that the number of watches is correct.

    Parameters
    ----------
    realtime_enabled : Boolean
        Tells if realtime is enabled
    decreases_num_watches : Boolean
        Tells if the number of watches must decrease
    rename_folder : Boolean
        Tells if the folder must be renamed
    """
    check_apply_test({'num_watches_conf'}, get_configuration['tags'])

    if ((get_configuration['metadata']['fim_mode'] == "scheduled" and realtime_enabled) or
            (get_configuration['metadata']['fim_mode'] == "realtime" and not realtime_enabled)):
        pytest.skip("Does not apply to this config file")

    # Check that the number of inotify watches is correct before modifying the folder
    try:
        num_watches = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                              callback=callback_num_inotify_watches,
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
            if decreases_num_watches and not rename_folder:   # Delete folder
                assert num_watches == str(EXPECTED_WATCHES), 'Wrong number of inotify watches before deleting folder'
            elif decreases_num_watches and rename_folder:   # Rename folder
                assert num_watches == str(EXPECTED_WATCHES), 'Wrong number of inotify watches before renaming folder'
            elif not decreases_num_watches and not rename_folder:   # Not modifying the folder
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
        num_watches = wazuh_log_monitor.start(timeout=40,
                                              callback=callback_num_inotify_watches,
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
            if decreases_num_watches and not rename_folder:   # Delete folder
                assert num_watches == str(NO_WATCHES), 'Wrong number of inotify watches after deleting folder'
            elif decreases_num_watches and rename_folder:   # Rename folder
                assert num_watches == str(NO_WATCHES), 'Wrong number of inotify watches after renaming folder'
            elif not decreases_num_watches and not rename_folder:   # Not modifying the folder
                error_msg = 'Wrong number of inotify watches when not modifying the folder'
                assert num_watches == str(EXPECTED_WATCHES), error_msg
        else:
            pytest.fail('Wrong number of inotify watches')

    # If directories have been removed or renamed, create directories again and check Wazuh add watches
    if decreases_num_watches:
        for directory in test_directories:
            os.mkdir(directory)

        num_watches = wazuh_log_monitor.start(timeout=40,
                                              callback=callback_num_inotify_watches,
                                              error_message='Did not receive expected '
                                              '"Folders monitored with real-time engine: ..." event'
                                              ).result()

        assert (num_watches and num_watches != EXPECTED_WATCHES), 'Watches not added'
