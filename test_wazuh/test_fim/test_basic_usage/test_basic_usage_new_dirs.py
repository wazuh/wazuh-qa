# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil

import pytest

from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.fim import DEFAULT_TIMEOUT, LOG_FILE_PATH, generate_params, \
    regular_file_cud, check_time_travel


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]


# Variables

test_directories = []
directory_str = os.path.join(PREFIX, 'testdir1')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
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
    """Check that a new monitored directory generates events after the next scheduled scan.

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

    # Create the monitored directory with files and check that events are not raised
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file1', 'file2', 'file3'],
                     min_timeout=DEFAULT_TIMEOUT, triggers_event=False)

    # Travel to the future to start next scheduled scan
    check_time_travel(True)

    # Assert that events of new CUD actions are raised after next scheduled scan
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file4', 'file5', 'file6'],
                     min_timeout=DEFAULT_TIMEOUT, triggers_event=True)
