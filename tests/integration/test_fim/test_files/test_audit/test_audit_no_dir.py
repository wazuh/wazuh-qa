# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
import shutil
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params, callback_audit_unable_dir, callback_audit_added_rule
from wazuh_testing.tools import PREFIX, LOG_FILE_PATH, ALERT_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables

test_directories = []
testdir = os.path.join(PREFIX, 'testdir')
filename = 'testfile'
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
wazuh_alert_monitor = FileMonitor(ALERT_FILE_PATH)

# Configurations

p, m = generate_params(extra_params={'TEST_DIRECTORIES': testdir}, modes=['whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    # Check that the directory does not exist and that Auditd is active.
    assert not os.path.exists(testdir), 'Directory should not exist before test'

    if sys.platform != 'win32':
        status = os.system('systemctl is-active --quiet auditd')
        assert status == 0, 'Audit daemon is not active before performing the test.'


def extra_configuration_after_yield():
    # Remove directory after test
    shutil.rmtree(testdir, ignore_errors=True)


@pytest.mark.parametrize('tags_to_apply', [
    {'audit_no_dir'}
])
def test_audit_no_dir(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """Monitor non-existent directory in whodata. Check that it is added to the rules after creating it.

    The audit thread runs always a directory that is configured to be monitored in
    who-data mode. Doesn't matter if it exists at start-up or not. Once that thread
    is up, the audit rules are reloaded every 30 seconds (not configurable), so
    when the directory is created, it starts to be monitored.

    Parameters
    ----------
    tags_to_apply : set
        Configuration tag to apply in the test
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Assert message is generated: Unable to add audit rule for ....
    result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_audit_unable_dir,
                                     error_message='Did not receive message "Unable to add audit rule for ..."'
                                     ).result()
    assert result == testdir, f'{testdir} not in "Unable to add audit rule for {result}" message'

    # Create the directory and verify that it is added to the audit rules. It is checked every 30 seconds.
    os.makedirs(testdir)
    result = wazuh_log_monitor.start(timeout=30, callback=callback_audit_added_rule,
                                     error_message='Folders were not added to Audit rules list').result()
    assert result == testdir, f'{testdir} not in "Added audit rule for monitoring directory: {result}" message'
