# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file

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


@pytest.mark.parametrize('removed, renamed', [
    (True, False),
    (False, True)
])
def test_readded_watches(removed, renamed, get_configuration, configure_environment, restart_syscheckd_each_time):
    """
    Check if Wazuh delete watches when directory is removed or renamed, and add watches when directory is readded.

    Parameters
    ----------
    removed : Boolean
        Tells if the directory must be removed
    renamed : Boolean
        Tells if the directory must be renamed
    """

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
    assert(directory == testdir), 'Unexpected path'

    # Create directories again and check Wazuh add watches
    os.mkdir(testdir)

    num_watches = wazuh_log_monitor.start(timeout=40, callback=callback_num_inotify_watches,
                                          error_message='Did not receive expected '
                                          '"Folders monitored with real-time engine: ..." event'
                                          ).result()

    assert (num_watches and num_watches != EXPECTED_WATCHES), 'Watches not added'
    regular_file_cud(testdir, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, triggers_event=True)
