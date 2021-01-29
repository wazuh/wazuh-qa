# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from test_fim.test_files.test_follow_symbolic_link.common import wait_for_symlink_check, wait_for_audit, \
    symlink_interval, \
    modify_symlink
from wazuh_testing import global_parameters, logger
from wazuh_testing.fim import SYMLINK, REGULAR, LOG_FILE_PATH, generate_params, create_file, change_internal_options, \
    callback_detect_event, check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables

test_directories = [os.path.join(PREFIX, 'testdir'), os.path.join(PREFIX, 'testdir_target')]
testdir = test_directories[0]
testdir_link = os.path.join(PREFIX, 'testdir_link')
testdir_target = test_directories[1]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations

conf_params, conf_metadata = generate_params(extra_params={'FOLLOW_MODE': 'yes'})
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Create files and symlinks"""
    create_file(REGULAR, testdir_target, 'regular1')
    create_file(SYMLINK, PREFIX, 'testdir_link', target=testdir)
    # Set symlink_scan_interval to a given value
    change_internal_options(param='syscheck.symlink_scan_interval', value=symlink_interval)


def extra_configuration_after_yield():
    """Set symlink_scan_interval to default value and remove symbolic link"""
    os.remove(testdir_link)
    change_internal_options(param='syscheck.symlink_scan_interval', value=600)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'symlink_and_dir'},
])
def test_symlink_dir_inside_monitored_dir(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                          wait_for_fim_start):
    """
    Monitor a directory and a symbolic link to it, change the target of the symbolic link.

    The directory must be scanned silently, preventing events from triggering until it has finished.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'

    # Modify the symbolic link and expect no events
    modify_symlink(testdir_target, testdir_link)

    # Wait for both audit and the symlink check to run
    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(whodata, wazuh_log_monitor)

    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Create a file in the pointed folder and expect events
    create_file(REGULAR, testdir_link, 'regular2')

    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected '
                                          '"Sending FIM event: ..." event')
