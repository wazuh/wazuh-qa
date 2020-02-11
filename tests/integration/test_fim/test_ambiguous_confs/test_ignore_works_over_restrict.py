# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_ignore, callback_detect_event, create_file, REGULAR, \
    generate_params, check_time_travel
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = pytest.mark.tier(level=2)

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_ignore_restrict_win32.yaml' if sys.platform == 'win32'
                                   else 'wazuh_conf_ignore_restrict.yaml')

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
testdir1, testdir2 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations

conf_params, conf_metadata = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('folder, filename, triggers_event, tags_to_apply', [
    (testdir1, 'testfile', False, {'valid_no_regex'}),
    (testdir2, 'not_ignored_string', True, {'valid_no_regex'}),
    (testdir1, 'testfile2', False, {'valid_regex'}),
    (testdir1, 'ignore_testfile2', False, {'valid_regex'}),
    (testdir2, 'not_ignored_sregex', True, {'valid_regex'})
])
def test_ignore_works_over_restrict(folder, filename, triggers_event, tags_to_apply, get_configuration,
                                    configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check if the ignore tag prevails over the restrict one when using both in the same directory.

    This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.

    Parameters
    ----------
    folder : str
        Directory where the file is being created
    filename : str
        Name of the file to be created
    triggers_event : bool
        True if an event must be generated, False otherwise
    tags_to_apply : set
        Run test if it matches with a configuration identifier, skip otherwise

    """
    print('[INFO] Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create file that must be ignored
    print(f'[INFO] Adding file {os.path.join(testdir1, filename)}, content: ""')
    create_file(REGULAR, folder, filename, content='')

    # Go ahead in time to let syscheck perform a new scan if mode is scheduled
    print(f'[INFO] Time travel: {scheduled}')
    check_time_travel(scheduled)
    error_message = f'[ERROR] Did not receive expected event for file {os.path.join(testdir1, filename)}'

    if triggers_event:
        print('[INFO] Checking the event...')
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message=error_message).result()

        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(folder, filename), 'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_ignore,
                                                   error_message=error_message).result()

            if ignored_file == os.path.join(folder, filename):
                break
