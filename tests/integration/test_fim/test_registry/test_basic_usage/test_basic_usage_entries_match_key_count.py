# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, timedelta, callback_registry_count_entries,  \
     check_time_travel, create_registry, modify_registry_value, delete_registry, registry_parser
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

if sys.platform == 'win32':
    import win32api
    import win32con

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
registry_key = "HKEY_LOCAL_MACHINE"
registry_subkey = "SOFTWARE\\Classes\\testkey"
arch = win32con.KEY_WOW64_32KEY
registry_str = ",".join(os.path.join(registry_key, registry_subkey))
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': registry_str}
attributes = [{'tags': 'test_tag'}]
configurations_path = os.path.join(test_data_path, 'wazuh_conf_reg_attr.yaml')
p, m = generate_params(extra_params=conf_params, apply_to_all=({'ATTRIBUTE': attr} for attr in attributes),
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

def extra_configuration_after_yield():
    """Make sure to delete the key after performing the test"""
    try:
        delete_registry(registry_parser[registry_key], registry_subkey, arch)
    except win32api.error:
        pass


def extra_configuration_before_yield():
    key_h = create_registry(registry_parser[registry_key], registry_subkey, arch)

    modify_registry_value(key_h, 'value1', win32con.REG_SZ, 'some value')
    modify_registry_value(key_h, 'value2', win32con.REG_DWORD, 123456)
    modify_registry_value(key_h, 'value3', win32con.REG_QWORD, 654321)


def test_entries_match_key_count(get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Check if FIM entries match the path count

    It creates two regular files, a symlink and a hard link before the scan begins. After events are logged,
    we should have 3 inode entries and a path count of 4.
    """
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    values, keys = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_registry_count_entries,
                                                  error_message='Did not receive expected '
                                                                '"Fim inode entries: ..., path count: ..." event'
                                                  ).result()
    check_time_travel(True, monitor=wazuh_log_monitor)

    if values and keys:
        assert values == '3' and keys == '1', 'Wrong number of keys and values'
    else:
        raise AssertionError('Wrong number of keys and values')
