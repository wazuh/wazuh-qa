# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
from collections import Counter

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_registry, modify_registry, delete_registry, \
    callback_detect_event, check_time_travel, validate_event, registry_parser
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

import win32api
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
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_both.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('registry_key, registry_subkey, arch, value_list', [
    (key, sub_key_1, win32con.KEY_WOW64_64KEY, ['value1', 'value2', 'value3']),
    (key, sub_key_2, win32con.KEY_WOW64_32KEY, ['value1', 'value2', 'value3']),
    (key, sub_key_2, win32con.KEY_WOW64_64KEY, ['value1', 'value2', 'value3'])

])
def test_delete_registry(registry_key, registry_subkey, arch, value_list,
                       get_configuration, configure_environment,
                       restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheckd detects 'deleted' events from the values contained
    in a registry key that is being deleted.

    Parameters
    ----------
    registry_key : str
        Root key where the sub key will be created (HKEY_LOCAL_MACHINE, etc)
    registry_subkey : str
        Path of the registry subkey
    value_list : list
        Names of the values.
    """

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    key_h = create_registry(registry_parser[registry_key], registry_subkey, arch)
    # Create values inside subkey
    for value in value_list:
        modify_registry(key_h, value, win32con.REG_SZ, "some content")

    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            accum_results=len(value_list) + 1, error_message='Did not receive expected '
                                                                        '"Sending FIM event: ..." event').result()
    for ev in events:
        validate_event(ev, mode=mode)

    # Remove registry
    delete_registry(registry_parser[registry_key], registry_subkey, arch)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    # Expect deleted events
    event_list = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event',
                                         accum_results=len(value_list) + 1).result()
    path_list = set([event['data']['path'] for event in event_list])
    counter_type = Counter([event['data']['type'] for event in event_list])
    for ev in events:
        validate_event(ev, mode=mode)

    assert counter_type['deleted'] == len(value_list) + 1, f'Number of "deleted" events should be {len(value_list) + 1}'

    for value in value_list:
        assert os.path.join(value_list, value) in path_list, f'Value {value} not found within the events'
