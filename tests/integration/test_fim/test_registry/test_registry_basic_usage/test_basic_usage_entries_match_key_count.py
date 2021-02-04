# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_registry_count_entries, \
    check_time_travel, create_registry, modify_registry_value, registry_parser, KEY_WOW64_64KEY, \
    REG_SZ, REG_MULTI_SZ, REG_DWORD
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

arch = KEY_WOW64_64KEY
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"

test_regs = [os.path.join(key, sub_key_1)]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
reg1 = os.path.join(key, sub_key_1)

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_reg_attr.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def extra_configuration_before_yield():
    key_h = create_registry(registry_parser[key], sub_key_1, arch)

    modify_registry_value(key_h, "value1", REG_SZ, "some content")
    modify_registry_value(key_h, "value2", REG_MULTI_SZ, "some content\0second string\0")
    modify_registry_value(key_h, "value3", REG_DWORD, 1234)


def test_entries_match_key_count(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if FIM entries match the entries count
    """

    entries = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                      callback=callback_registry_count_entries,
                                      error_message='Did not receive expected '
                                                    '"Fim inode entries: ..., path count: ..." event'
                                      ).result()
    check_time_travel(True, monitor=wazuh_log_monitor)

    if entries:
        assert entries == '4', 'Wrong number of entries'
    else:
        raise AssertionError('Wrong number of entries')
