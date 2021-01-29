# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_detect_event, \
    modify_registry_value, callback_detect_end_scan, registry_parser, create_registry, KEY_WOW64_64KEY, \
    KEY_WOW64_32KEY, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

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
reg1, reg2 = test_regs

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1, 'WINDOWS_REGISTRY_2': reg2}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_both.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

registry_list = [(key, sub_key_1, KEY_WOW64_64KEY),
                 (key, sub_key_2, KEY_WOW64_32KEY),
                 (key, sub_key_2, KEY_WOW64_64KEY)]


# fixtures

@pytest.fixture(scope='function')
def restart_syscheckd_each_time(request):
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon='wazuh-syscheckd')


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


@pytest.mark.parametrize('key, subkey, arch, value_type, content', [
    (key, sub_key_1, KEY_WOW64_64KEY, REG_SZ, 'added'),
    (key, sub_key_2, KEY_WOW64_32KEY, REG_SZ, 'added'),
    (key, sub_key_2, KEY_WOW64_64KEY, REG_SZ, 'added')
])
def test_wait_until_baseline(key, subkey, arch, value_type, content, get_configuration,
                             configure_environment, restart_syscheckd_each_time):
    """
    Check if events are appearing after the baseline
    The message 'File integrity monitoring scan ended' informs about the end of the first scan,
    which generates the baseline
    """

    key_handle = create_registry(registry_parser[key], subkey, arch)

    modify_registry_value(key_handle, "value_name", value_type, content)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event_before_end_scan,
                            error_message='Did not receive expected event before end the scan')
