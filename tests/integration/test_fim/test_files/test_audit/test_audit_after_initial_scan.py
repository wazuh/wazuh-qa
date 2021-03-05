# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
import shutil
import subprocess

import pytest
import wazuh_testing.fim as fim

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test

@pytest.mark.parametrize('tags_to_apply, folder', [
    ({'config1'}, testdir1),
    ({'config1'}, testdir2),
    ({'config1'}, testdir3)
])
def test_remove_and_read_folder(tags_to_apply, folder, get_configuration,
                                configure_environment, restart_syscheckd,
                                wait_for_fim_start):
    """Remove folder which is monitored with auditd and then create it again.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        folder (str): The folder to remove and read.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    shutil.rmtree(folder, ignore_errors=True)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_audit_removed_rule,
                            error_message=f'Did not receive expected "removed" event '
                                          f'removing the folder {folder}')

    os.makedirs(folder, mode=0o777)
    fim.wait_for_audit(True, wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_audit_added_rule,
                            error_message='Did not receive expected "added" event')


@pytest.mark.parametrize('tags_to_apply', [
    {'config1'}
])
def test_reconnect_to_audit(tags_to_apply, get_configuration, configure_environment,
                            restart_syscheckd, wait_for_fim_start):
    """Restart auditd and check Wazuh reconnect to auditd

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    restart_command = ["service", "auditd", "restart"]
    subprocess.run(restart_command, check=True)

    wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_connection_close,
                            error_message='Did not receive expected "audit connection close" event')
    wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_connection,
                            error_message='Did not receive expected "audit connection" event')
