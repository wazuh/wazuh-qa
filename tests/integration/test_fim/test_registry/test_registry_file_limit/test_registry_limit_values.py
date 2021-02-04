# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_value_file_limit, generate_params, \
    callback_registry_count_entries, modify_registry_value, registry_parser, KEY_WOW64_64KEY, REG_SZ, KEY_ALL_ACCESS, \
    RegOpenKeyEx, RegCloseKey

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks


pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables


KEY = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"

test_regs = [os.path.join(KEY, sub_key_1)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1 = test_regs[0]

# Configurations


file_limit_list = ['1', '10', '100', '1000']

conf_params = {'WINDOWS_REGISTRY': reg1, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'FILE_LIMIT': file_limit_elem} for file_limit_elem in file_limit_list),
                       modes=['scheduled'])

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Functions


def extra_configuration_before_yield():
    """Generate registry entries to fill database"""
    reg1_handle = RegOpenKeyEx(registry_parser[KEY], sub_key_1, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    for i in range(0, int(file_limit_list[-1]) + 10):
        modify_registry_value(reg1_handle, f'value_{i}', REG_SZ, 'added')

    RegCloseKey(reg1_handle)

# Tests


@pytest.mark.parametrize('tags_to_apply', [
    {'file_limit_registry_conf'}
])
def test_file_limit_values(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check that a list of different values gets configured correctly in file_limit.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file_limit_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=callback_value_file_limit,
                                               error_message='Did not receive expected '
                                               '"DEBUG: ...: Maximum number of entries to be monitored: ..." event'
                                               ).result()

    if file_limit_value:
        assert file_limit_value == get_configuration['metadata']['file_limit'], 'Wrong value for file_limit.'
    else:
        pytest.fail('Wrong value for file_limit')

    entries = wazuh_log_monitor.start(timeout=40,
                                      callback=callback_registry_count_entries,
                                      error_message='Did not receive expected '
                                      '"Fim inode entries: ..., path count: ..." event'
                                      ).result()

    if entries:
        assert entries == str(get_configuration['metadata']['file_limit']), 'Wrong number of entries count.'
    else:
        pytest.fail('Wrong number of entries count')
