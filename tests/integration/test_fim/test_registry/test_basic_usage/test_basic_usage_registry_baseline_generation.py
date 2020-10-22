# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from time import time

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, delete_registry, timedelta, callback_detect_event, \
    check_time_travel, create_registry, registry_value_cud, callback_detect_end_scan, registry_parser
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

from wazuh_testing import global_parameters

import win32con


# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"

test_regs = [os.path.join(key, sub_key_1), os.path.join(key, sub_key_2)]
registry_str = ",".join(test_regs)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
registr_str, registry2 = test_regs

monitoring_modes = ['scheduled', 'scheduled']

# Configurations


conf_params = {'WINDOWS_REGISTRY_1': registr_str, 'WINDOWS_REGISTRY_2' : registry2}
attributes = [{'tags': 'test_tag'}]
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_both.yaml')
p, m = generate_params(extra_params=conf_params, apply_to_all=({'ATTRIBUTE': attr} for attr in attributes),
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

registry_list = [(key, sub_key_1, win32con.KEY_WOW64_32KEY),
                 (key, sub_key_2, win32con.KEY_WOW64_32KEY),
                 (key, sub_key_2, win32con.KEY_WOW64_64KEY)]
# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def callback_detect_event_before_end_scan(line):
    ended_scan = callback_detect_end_scan(line)
    if ended_scan is None:
        event = callback_detect_event(line)
        assert event is None, 'Event detected before end scan'
        return None
    else:
        return True


def extra_configuration_before_yield():
    for key, subkey, arch in registry_list:
        create_registry(registry_parser[key], subkey, arch)


def extra_configuration_after_yield():
    """Make sure to delete the key after performing the test"""
    for key, subkey, arch in registry_list:
        try:
            delete_registry(registry_parser[key], subkey, arch)
        except win32api.error:
            pass


@pytest.mark.parametrize('registry_key, registry_subkey, arch', [
    (key, sub_key_1, win32con.KEY_WOW64_64KEY),
    (key, sub_key_2, win32con.KEY_WOW64_32KEY),
    (key, sub_key_2, win32con.KEY_WOW64_64KEY)
])
def test_basic_usage_registry_baseline_generation(registry_key, registry_subkey, arch,
                                                  get_configuration, configure_environment, restart_syscheckd):
    """
    Check if events are appearing after the baseline
    The message 'File integrity monitoring scan ended' informs about the end of the first scan,
    which generates the baseline
    """
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    # Create a file during initial scan to check if the event is logged after the 'scan ended' message
    registry_value_cud(key, registry_subkey, arch,  wazuh_log_monitor, time_travel=True)

    wazuh_log_monitor.start(timeout=120, callback=callback_detect_event_before_end_scan,
                            error_message='Did not receive expected event before end the scan')
