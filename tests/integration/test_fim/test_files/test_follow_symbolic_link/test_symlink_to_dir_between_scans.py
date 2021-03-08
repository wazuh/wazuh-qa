# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from shutil import rmtree

import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import wait_for_symlink_check, symlink_interval, \
    testdir_link, testdir_target
from wazuh_testing import global_parameters

from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'}, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Create files and symlinks"""
    symlinkdir = testdir_link

    os.makedirs(testdir_target, exist_ok=True, mode=0o777)
    fim.create_file(fim.REGULAR, testdir_target, 'regular1')
    fim.create_file(fim.SYMLINK, PREFIX, symlinkdir, target=testdir_target)
    # Set symlink_scan_interval to a given value
    fim.change_internal_options(param='syscheck.symlink_scan_interval', value=symlink_interval)


def extra_configuration_after_yield():
    """Set symlink_scan_interval to default value"""
    rmtree(testdir_link, ignore_errors=True)
    rmtree(testdir_target, ignore_errors=True)
    fim.change_internal_options(param='syscheck.symlink_scan_interval', value=600)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'replace_with_directory'},
])
def test_symlink_to_dir_between_scans(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                      wait_for_fim_start):
    """Replace a link with a directory between scans.

    This test monitors a link with `follow_symbolic_link` enabled. After the first scan, it is replaced with a directory,
    the new directory should send alerts during a second scan.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If a expected event wasn't triggered.
        AttributeError: If a unexpected event was captured.
        ValueError: If the event's type and path are not the expected.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    regular2 = 'regular2'

    # Delete symbolic link and create a folder with the same name
    os.remove(testdir_link)
    os.makedirs(testdir_link, exist_ok=True, mode=0o777)
    fim.create_file(fim.REGULAR, testdir_link, regular2)

    # Wait for both audit and the symlink check to run
    wait_for_symlink_check(wazuh_log_monitor)
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)

    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                    error_message='Did not receive expected '
                                                  '"Sending FIM event: ..." event').result()

    assert 'added' in event['data']['type'] and regular2 in event['data']['path'], \
        f'"added" event not matching for {event}'
