
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_file_limit_capacity, generate_params, create_file, \
                               check_time_travel, REGULAR, delete_file, callback_file_limit_back_to_normal
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine

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

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1}, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('tags_to_apply', [
    {'file_limit_capacity_alerts'}
])
def test_file_limit_capacity_alert_80(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                      wait_for_initial_scan):
    """
    Checks that the corresponding alerts appear in schedule mode for different capacity thresholds.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test 80% capacity
    # Create files
    for i in range(81):
        create_file(REGULAR, testdir1, f'test{i}')

    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(True, monitor=wazuh_log_monitor)

    file_limit_capacity = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_file_limit_capacity,
                                                  error_message='Did not receive expected '
                                                  '"DEBUG: ...: Sending DB 80% full alert." event'
                                                  ).result()

    if file_limit_capacity:
        assert file_limit_capacity == '80', 'Wrong capacity log for DB file_limit'
    else:
        raise AssertionError('Wrong capacity log for DB file_limit')


@pytest.mark.parametrize('tags_to_apply', [
    {'file_limit_capacity_alerts'}
])
def test_file_limit_capacity_alert_90(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                      wait_for_initial_scan):
    """
    Checks that the corresponding alerts appear in schedule mode for different capacity thresholds.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test 90% capacity
    # Create files
    for i in range(10):
        create_file(REGULAR, testdir1, f'test{81+i}')

    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(True, monitor=wazuh_log_monitor)

    file_limit_capacity = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_file_limit_capacity,
                                                  error_message='Did not receive expected '
                                                  '"DEBUG: ...: Sending DB 90% full alert." event'
                                                  ).result()

    if file_limit_capacity:
        assert file_limit_capacity == '90', 'Wrong capacity log for DB file_limit'
    else:
        raise AssertionError('Wrong capacity log for DB file_limit')


@pytest.mark.parametrize('tags_to_apply', [
    {'file_limit_capacity_alerts'}
])
def test_file_limit_capacity_alert_normal(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                          wait_for_initial_scan):
    """
    Checks that the corresponding alerts appear in schedule mode for different capacity thresholds.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test back to normal capacity
    # Remove files
    for i in range(91):
        delete_file(testdir1, f'test{i}')

    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(True, monitor=wazuh_log_monitor)

    event_found = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=callback_file_limit_back_to_normal,
                                          error_message='Did not receive expected '
                                          '"DEBUG: ...: Sending DB back to normal alert." event'
                                          ).result()

    assert event_found, 'Event "Sending DB back to normal alert." not found'
