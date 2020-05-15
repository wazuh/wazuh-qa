# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
import time

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import detect_initial_scan
from wazuh_testing.fim import generate_params, regular_file_cud, callback_non_existing_monitored_dir
from wazuh_testing.tools import PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

test_directories = []
directory_str = os.path.join(PREFIX, 'testdir1')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path,
                                   'wazuh_conf_new_dirs.yaml' if sys.platform != 'win32'
                                   else 'wazuh_conf_new_dirs_win32.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations
windows_audit_interval = 1
conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__,
               'WINDOWS_AUDIT_INTERVAL': str(windows_audit_interval)}
p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Make sure to delete any existing directory with the same name before performing the test"""
    shutil.rmtree(directory_str, ignore_errors=True)


def extra_configuration_after_yield():
    """Make sure to delete the directory after performing the test"""
    shutil.rmtree(directory_str, ignore_errors=True)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
def test_new_directory(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                       wait_for_initial_scan):
    """
    Check that a new monitored directory generates events after the next scheduled scan.

    This test performs the following steps:
    - Monitor a directory that does not exist.
    - Create the directory with files inside. Check that this does not produce events in ossec.log.
    - Move time forward to the next scheduled scan.
    - Check that now creating files within the directory do generate events.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if sys.platform != 'win32':
        # Create the monitored directory with files and check that events are not raised
        regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file1', 'file2', 'file3'],
                         min_timeout=global_parameters.default_timeout, triggers_event=False)

        detect_initial_scan(wazuh_log_monitor)
    else:
        # Wait for syscheck to realize the directories don't exist
        wazuh_log_monitor.start(timeout=10, callback=callback_non_existing_monitored_dir,
                                error_message='Monitoring discarded message not found')
        os.makedirs(directory_str, exist_ok=True, mode=0o777)
        time.sleep(windows_audit_interval+0.5)

    # Assert that events of new CUD actions are raised after next scheduled scan
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file4', 'file5', 'file6'],
                     min_timeout=40, triggers_event=True)
