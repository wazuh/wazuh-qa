# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import itertools
import glob
import os
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, callback_audit_key, callback_audit_health_check
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

testdir1 = os.path.join('/', 'testdir1')
test_directories = [testdir1]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# fixtures

@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'wazuh_whodata.conf')))
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_restart_audit(folder, name, content, get_configuration, configure_environment, restart_syscheckd, 
                       wait_for_initial_scan):
    # Todo
    return


def test_audit_key(folder, name, content, get_configuration, configure_environment, restart_syscheckd, 
                   wait_for_initial_scan):
    #check_apply_test("audit_key", get_configuration['tags'])
    
    audit_key = "custom_audit_key"
    audit_dir = "/testdir1"
    
    # Insert watch rule
    os.system("auditctl -w " + audit_dir + " -p wa -k " + audit_key)

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=callback_audit_key,
                                     accum_results=1).result()

    assert (audit_key in events)

    # Remove watch rule
    os.system("auditctl -W " + audit_dir + " -p wa -k " + audit_key)


@pytest.mark.parametrize('tags_to_apply', [
    ({'all'})
])
def test_audit_health_check(tags_to_apply, get_configuration,
                            configure_environment, restart_syscheckd):
    """Checks if the health check is passed."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_health_check)
