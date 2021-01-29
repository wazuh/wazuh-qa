# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_file_limit_capacity, generate_params, create_file, \
    check_time_travel, REGULAR, delete_file, callback_file_limit_back_to_normal, \
    callback_entries_path_count
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# Configurations


file_limit_list = ['100']
conf_params = {'TEST_DIRECTORIES': testdir1, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params, modes=['scheduled'],
                       apply_to_all=({'FILE_LIMIT': file_limit_elem} for file_limit_elem in file_limit_list))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('percentage,tags_to_apply', [
    (80, {'file_limit_conf'}),
    (90, {'file_limit_conf'}),
    (0, {'file_limit_conf'})
])
def test_file_limit_capacity_alert(percentage, tags_to_apply, get_configuration, configure_environment,
                                   restart_syscheckd, wait_for_fim_start):
    """
    Checks that the corresponding alerts appear in schedule mode for different capacity thresholds.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    NUM_FILES = percentage + 1

    if percentage == 0:
        NUM_FILES = 0

    if percentage >= 80:  # Percentages 80 and 90
        for i in range(NUM_FILES):
            create_file(REGULAR, testdir1, f'test{i}')
    else:  # Database back to normal
        for i in range(91):
            delete_file(testdir1, f'test{i}')

    check_time_travel(True, monitor=wazuh_log_monitor)

    if percentage >= 80:  # Percentages 80 and 90
        file_limit_capacity = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                      callback=callback_file_limit_capacity,
                                                      error_message='Did not receive expected '
                                                                    '"DEBUG: ...: Sending DB ...% full alert." event'
                                                      ).result()

        if file_limit_capacity:
            assert file_limit_capacity == str(percentage), 'Wrong capacity log for DB file_limit'
        else:
            raise AssertionError('Wrong capacity log for DB file_limit')
    else:  # Database back to normal
        event_found = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                              callback=callback_file_limit_back_to_normal,
                                              error_message='Did not receive expected '
                                                            '"DEBUG: ...: Sending DB back to normal alert." event'
                                              ).result()

        assert event_found, 'Event "Sending DB back to normal alert." not found'

    entries, path_count = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_entries_path_count,
                                                  error_message='Did not receive expected '
                                                                '"Fim inode entries: ..." event'
                                                  ).result()

    check_time_travel(True, monitor=wazuh_log_monitor)

    if sys.platform != 'win32':
        if entries and path_count:
            assert entries == str(NUM_FILES) and path_count == str(NUM_FILES), 'Wrong number of inodes and path count'
        else:
            raise AssertionError('Wrong number of inodes and path count')
    else:
        if entries:
            assert entries == str(NUM_FILES), 'Wrong number of entries count'
        else:
            raise AssertionError('Wrong number of entries count')
