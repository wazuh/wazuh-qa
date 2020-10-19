# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, timedelta, callback_detect_event,  \
     check_time_travel, registry_value_cud, create_registry, delete_registry, registry_parser
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from win32api

import win32con

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"

handle_list = list()
test_regs = [os.path.join(key, sub_key_1), os.path.join(key, sub_key_2)]
registry_str = ",".join(test_regs)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
registr_str, registry2 = test_regs

registry_list = [(sub_key_1, win32con.KEY_WOW64_64KEY), (sub_key_2, win32con.KEY_WOW64_32KEY),
                 (sub_key_2, win32con.KEY_WOW64_64KEY)]

monitoring_modes = ['scheduled', 'scheduled']

# Configurations


conf_params = {'WINDOWS_REGISTRY_1': registr_str, 'WINDOWS_REGISTRY_2' : registry2}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_both.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def extra_configuration_before_yield():
    """Make sure to delete any existing key with the same name before performing the test"""
    for reg_key, arch in registry_list:
        try:
            delete_registry(registry_parser[key], reg_key, arch)
        except win32api.error:  # Ignore the error in case the key doesn't exists
            pass


def extra_configuration_after_yield():
    """Make sure to delete the key after performing the test"""
    for reg_key, arch in registry_list:
        try:
            delete_registry(registry_parser[key], reg_key, arch)
        except win32api.error:  # Ignore the error in case the key doesn't exists
            pass


@pytest.mark.parametrize('registry_key, registry_subkey, arch', [
    (key, sub_key_1, win32con.KEY_WOW64_64KEY),
    (key, sub_key_2, win32con.KEY_WOW64_32KEY),
    (key, sub_key_2, win32con.KEY_WOW64_64KEY)
])
def test_basic_usage_registry_changes(registry_key, registry_subkey, arch, get_configuration, configure_environment,
                                      restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheckd detects value changes (add, modify, delete)

    Parameters
    ----------
    registry_key : str
        Root of the registry key (HKEY_* constants)
    registry_subkey : str
        Path of the registry
    arch : str
        Architecture
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    def shared_registry_validator_after_modify(event):
        assert event['data']['type'] == 'modified'
        assert '[x64]' in event['data'].get('path'),  f'Architecture is not correct'

    create_registry(registry_parser[key], registry_subkey, 0, arch)

    registry_value_cud(registry_key, registry_subkey, arch, wazuh_log_monitor, value_list={'value_name': 'asdfg'},
                       time_travel=True, validators_after_update=[shared_registry_validator_after_modify])
