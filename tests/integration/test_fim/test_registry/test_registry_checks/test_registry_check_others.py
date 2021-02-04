# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import CHECK_MTIME, CHECK_PERM, \
    CHECK_SIZE, CHECK_SUM, CHECK_ALL, \
    CHECK_TYPE, LOG_FILE_PATH, REQUIRED_REG_VALUE_ATTRIBUTES, \
    REQUIRED_REG_KEY_ATTRIBUTES, generate_params, registry_value_cud, \
    registry_key_cud
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\testkey1"
sub_key_2 = "SOFTWARE\\testkey2"
sub_key_3 = "SOFTWARE\\testkey3"
sub_key_4 = "SOFTWARE\\testkey4"
sub_key_5 = "SOFTWARE\\testkey5"
sub_key_6 = "SOFTWARE\\testkey6"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2),
             os.path.join(key, sub_key_3),
             os.path.join(key, sub_key_4),
             os.path.join(key, sub_key_5),
             os.path.join(key, sub_key_6)
             ]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

key_all_attrs = REQUIRED_REG_KEY_ATTRIBUTES[CHECK_ALL]
value_all_attrs = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL]

params_list = [(key, sub_key_1, key_all_attrs, {CHECK_SUM}, True, True),
               (key, sub_key_2, key_all_attrs, {CHECK_SIZE}, True, True),
               (key, sub_key_3, key_all_attrs, {CHECK_TYPE}, True, False),
               (key, sub_key_4, set(), value_all_attrs, False, True),
               (key, sub_key_5, key_all_attrs - {CHECK_PERM}, value_all_attrs, True, True),
               (key, sub_key_6, {CHECK_MTIME, CHECK_PERM}, value_all_attrs, True, True)
               ]
#               key, subkey,    key attrs                value_attrs,     key_mod, value_mod
# Configurations

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'WINDOWS_REGISTRY_3': test_regs[2],
               'WINDOWS_REGISTRY_4': test_regs[3],
               'WINDOWS_REGISTRY_5': test_regs[4],
               'WINDOWS_REGISTRY_6': test_regs[5]
               }

configurations_path = os.path.join(test_data_path, 'wazuh_check_others.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('key, subkey, key_attr, value_attr, triggers_key_modification, triggers_value_modification',
                         params_list)
def test_check_others(key, subkey, key_attr, value_attr, triggers_key_modification, triggers_value_modification,
                      get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test the behaviour disabling different check options over the same key with check_all enabled.

    Example:
        check_all: "yes" check_size: "no" check_sum: "no".

    Parameters
    ----------
    key: str
        key of the directory (HKEY_* constants).
    subkey: str
        Path of the subkey.
    key_attr: set
        Set of options that are expected for key events.
    value_attr: set
        Set of options that are expected for value events.
    triggers_key_modification: boolean
        Specify if the given options generate key events.
    triggers_value_modification: boolean
        Specify if the given options generate value events.
    """
    check_apply_test({'test_others'}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, options=key_attr,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     triggers_event_modified=triggers_key_modification)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=value_attr, time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       triggers_event_modified=triggers_value_modification)
