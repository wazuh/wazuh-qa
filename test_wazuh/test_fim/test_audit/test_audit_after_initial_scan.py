# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import pytest
import os
import shutil
import subprocess

from wazuh_testing.fim import (LOG_FILE_PATH,
                               callback_audit_reloaded_rule,
                               callback_audit_removed_rule,
                               callback_audit_connection_close,
                               callback_audit_connection)
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


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
                                 wait_for_initial_scan):
    """Remove folder which is monitored with auditd and then create it again.

    Parameters
    ----------
    tags_to_apply : set
        Configuration tag to apply in the test
    folder : str
        The folder to remove and readd
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    shutil.rmtree(folder, ignore_errors=True)
    wazuh_log_monitor.start(timeout=20, callback=callback_audit_removed_rule)

    os.makedirs(folder, mode=0o777)
    wazuh_log_monitor.start(timeout=30, callback=callback_audit_reloaded_rule)


@pytest.mark.parametrize('tags_to_apply', [
    {'config1'}
])
def test_reconnect_to_audit(tags_to_apply, get_configuration, configure_environment,
                            restart_syscheckd, wait_for_initial_scan):
    """Restart auditd and check Wazuh reconnect to auditd

    Parameters
    ----------
    tags_to_apply : set
        Configuration tag to apply in the test
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    subprocess.run(["service", "auditd", "restart"], check=True)

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_connection_close)
    wazuh_log_monitor.start(timeout=20, callback=callback_audit_connection)
