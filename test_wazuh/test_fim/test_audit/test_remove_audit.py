# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import pytest
import os

from wazuh_testing.fim import LOG_FILE_PATH, callback_audit_cannot_start
from wazuh_testing.tools import FileMonitor, load_wazuh_configurations, check_apply_test


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


@pytest.fixture(scope='module')
def uninstall_install_audit():
    """
    Uninstall auditd before test and install after test
    """

    if os.system('yum remove audit --assumeyes') == -1:
        raise Exception("Can not uninstall auditd")

    yield

    if os.system('yum install audit --assumeyes') == -1:
        raise Exception("Can not install auditd")

    os.system('service auditd start')


# Test

@pytest.mark.parametrize('tags_to_apply', [
    {'config1'}
])
def test_move_folders_to_realtime(tags_to_apply, get_configuration, uninstall_install_audit,
                                  configure_environment, restart_syscheckd):
    """
    Check folders monitored with Whodata change to Real-time if auditd is not installed

    :param tags_to_apply Configuration tag to apply
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_cannot_start)
