# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params, delete_registry, registry_parser
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from win32api import RegOpenKeyEx
import win32con

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

registry_list=[(sub_key_1, win32con.KEY_WOW64_64KEY), (sub_key_2, win32con.KEY_WOW64_32KEY),
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
            key_h = RegOpenKeyEx(registry_parser[key], reg_key, 0, win32con.KEY_ALL_ACCESS | arch)
            delete_registry(key_h)
        except OSError: # Ignore the error in case the key doesn't exists
            pass


def extra_configuration_after_yield():
    """Make sure to delete the key after performing the test"""
    for key_h, _ in handle_list:
        try:
            delete_registry(key_h)
        except OSError:
            pass
