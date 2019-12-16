# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import timedelta

import pytest
import sys
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, callback_ignore, create_file, \
                              REGULAR, generate_params, check_time_travel, DEFAULT_TIMEOUT
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, TimeMachine, \
                                PREFIX

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path,
                                    'wazuh_conf_ignore_restrict_win32.yaml' if sys.platform == 'win32' else 'wazuh_conf_ignore_restrict.yaml')


test_directories = [os.path.join(PREFIX, 'testdir1')]

testdir1 = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
timeout = DEFAULT_TIMEOUT

# Configurations

conf_params, conf_metadata = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)

# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder, filename, tags_to_apply', [
    (testdir1, 'testfile', {'valid_no_regex'}),
    (testdir1, 'testfile2', {'valid_regex'})
])
def test_ignore_works_over_restrict(folder, filename, tags_to_apply, get_configuration, configure_environment,
                                    restart_syscheckd, wait_for_initial_scan):
    """
        Checks if the ignore tag prevails over the restrict one when using both in the same directory.

        This test is intended to be used with valid configurations files. Each execution of this test will configure
        the environment properly, restart the service and wait for the initial scan.

        :param folder string Directory where the file is being created
        :param filename string Name of the file to be created
        :param tags_to_apply set Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create file that must be ignored
    create_file(REGULAR, folder, filename, content='')

    # Check if any event has been sent
    check_time_travel(scheduled)

    while True:
        ignored_file = wazuh_log_monitor.start(timeout=timeout, callback=callback_ignore).result()

        if ignored_file == os.path.join(folder, filename):
            break
