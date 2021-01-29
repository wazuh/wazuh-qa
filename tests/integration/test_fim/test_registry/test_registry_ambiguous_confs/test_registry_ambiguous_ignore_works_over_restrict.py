# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, registry_key_cud, \
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
subkey_1 = "SOFTWARE\\testkey1"
subkey_2 = "SOFTWARE\\testkey2"

test_regs = [os.path.join(key, subkey_1),
             os.path.join(key, subkey_2)
             ]

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'RESTRICT_KEY_1': "restrict_key$",
               'RESTRICT_KEY_2': "key_restrict$",
               'REGISTRY_IGNORE': os.path.join(test_regs[0], "restrict_key"),
               'REGISTRY_IGNORE_REGEX': 'key_restrict$',
               'RESTRICT_VALUE_1': 'restrict_value$',
               'RESTRICT_VALUE_2': 'value_restrict$',
               'REGISTRY_IGNORE_VALUE': os.path.join(test_regs[0], "restrict_value"),
               'REGISTRY_IGNORE_VALUE_REGEX': 'value_restrict$'
               }

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_ignore_over_restrict.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('key, subkey, arch, key_name', [
    (key, subkey_1, KEY_WOW64_64KEY, 'restrict_key'),
    (key, subkey_1, KEY_WOW64_64KEY, 'key_restrict'),
    (key, subkey_2, KEY_WOW64_64KEY, 'key_restrict'),
    (key, subkey_2, KEY_WOW64_32KEY, 'key_restrict')
])
def test_ignore_over_restrict_key(key, subkey, key_name, arch,
                                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check registry values are ignored according to configuration.

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        path of the registry where the test will be executed.
    arch : str
        Architecture of the registry.
    """
    check_apply_test({"ambiguous_ignore_restrict_key"}, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, key_list=[key_name],
                     min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=False)


@pytest.mark.parametrize('key, subkey, arch, value_name', [
    (key, subkey_1, KEY_WOW64_64KEY, 'restrict_value'),
    (key, subkey_1, KEY_WOW64_64KEY, 'value_restrict'),
    (key, subkey_2, KEY_WOW64_64KEY, 'value_restrict'),
    (key, subkey_2, KEY_WOW64_32KEY, 'value_restrict')
])
def test_ignore_over_restrict_values(key, subkey, value_name, arch,
                                     get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check registry values are ignored according to configuration.

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        path of the registry where the test will be executed.
    arch : str
        Architecture of the registry.
    """
    check_apply_test({"ambiguous_ignore_restrict_values"}, get_configuration['tags'])

    # Test registry keys.
    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=[value_name],
                       min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=False)
