# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil as sh

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_num_inotify_watches, generate_params, check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_num_watches.yaml')
testdir1 = test_directories[0]

# Configurations

p, m = generate_params(extra_params={"TEST_DIRECTORIES": test_directories[0]})

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


def extra_configuration_before_yield():
    os.mkdir(testdir1)
    os.mkdir(os.path.join(testdir1, 'sub1'))
    os.mkdir(os.path.join(testdir1, 'sub2'))


def extra_configuration_after_yield():
    sh.rmtree(testdir1, ignore_errors=True)


@pytest.mark.parametrize('realtime_enabled, decreases_num_watches, rename_folder, tags_to_apply', [
    (True, True, False, 'num_watches_realtime_enabled'),
    (True, True, True, 'num_watches_realtime_enabled'),
    (True, False, False, 'num_watches_realtime_enabled'),
    (False, False, False, 'num_watches_realtime_disabled')
])
def test_num_watches(realtime_enabled, decreases_num_watches, rename_folder, tags_to_apply, get_configuration,
                     configure_environment, restart_syscheckd, wait_for_initial_scan):
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
    check_apply_test(tags_to_apply, get_configuration['tags'])

    num_watches = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=callback_num_inotify_watches,
                                          error_message='Did not receive expected '
                                          '"Folders monitored with inotify engine: ..." event'
                                          ).result()

    if num_watches:
        if not realtime_enabled:
            assert num_watches == '0', 'Wrong number of inotify watches'
        elif decreases_num_watches and not rename_folder:
            assert num_watches == '3', 'Wrong number of inotify watches'
        elif decreases_num_watches and rename_folder:
            assert num_watches == '3', 'Wrong number of inotify watches'
        elif not decreases_num_watches and not rename_folder:
            assert num_watches == '3', 'Wrong number of inotify watches'
    else:
        raise AssertionError('Wrong number of inotify watches')

    if realtime_enabled:
        if decreases_num_watches and not rename_folder:
            sh.rmtree(testdir1, ignore_errors=True)
        elif decreases_num_watches and rename_folder:
            os.rename(testdir1, 'changed_name')

    check_time_travel(True)

    num_watches = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=callback_num_inotify_watches,
                                          error_message='Did not receive expected '
                                          '"Folders monitored with inotify engine: ..." event'
                                          ).result()

    if num_watches:
        if not realtime_enabled:
            assert num_watches == '0', 'Wrong number of inotify watches'
        elif decreases_num_watches and not rename_folder:
            assert num_watches == '0', 'Wrong number of inotify watches'
        elif decreases_num_watches and rename_folder:
            assert num_watches == '0', 'Wrong number of inotify watches'
        elif not decreases_num_watches and not rename_folder:
            assert num_watches == '3', 'Wrong number of inotify watches'
    else:
        raise AssertionError('Wrong number of inotify watches')
