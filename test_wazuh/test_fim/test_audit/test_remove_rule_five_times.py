# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import pytest
import os

from wazuh_testing.fim import (LOG_FILE_PATH,
                               callback_audit_rules_manipulation,
                               callback_audit_deleting_rule)
from wazuh_testing.tools import (FileMonitor,
                                 load_wazuh_configurations,
                                 check_apply_test)


# All tests in this module apply to linux only
pytestmark = pytest.mark.linux


# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# Fixture

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test

@pytest.mark.parametrize('tags_to_apply, folder, audit_key', [
    ({'config1'}, '/testdir2', 'wazuh_fim')
])
def test_remove_rule_five_times(tags_to_apply, folder, audit_key, get_configuration,
                                 configure_environment, restart_syscheckd,
                                 wait_for_initial_scan):
    """
    Remove auditd rule using auditctl five times and check Wazuh ignores folder.

    :param tags_to_apply Configuration tag to apply in the test
    :param folder The folder to remove and readd
    :param audit_key The key which Wazuh put.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    for i in range(0, 5):
        os.system("auditctl -W " + folder + " -p wa -k " + audit_key)
        wazuh_log_monitor.start(timeout=20, callback=callback_audit_rules_manipulation)

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_deleting_rule)
