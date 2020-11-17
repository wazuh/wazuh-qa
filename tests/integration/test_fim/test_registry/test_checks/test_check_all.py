# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import CHECK_GROUP, CHECK_MTIME, CHECK_OWNER, CHECK_PERM, \
                              CHECK_SHA256SUM, CHECK_SIZE, CHECK_SUM, CHECK_ALL, \
                              CHECK_TYPE, LOG_FILE_PATH, REQUIRED_REG_VALUE_ATTRIBUTES, KEY_WOW64_32KEY, \
                              KEY_WOW64_64KEY, REQUIRED_REG_KEY_ATTRIBUTES, generate_params, registry_value_cud, \
                              registry_key_cud

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"
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

params_list = [(key, sub_key_1, key_all_attrs, value_all_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]),
               (key, sub_key_2, key_all_attrs, value_all_attrs - {CHECK_SHA256SUM}),
               (key, sub_key_3, key_all_attrs, value_all_attrs - {CHECK_TYPE}),
               (key, sub_key_4, key_all_attrs, value_all_attrs - {CHECK_SIZE}),
               (key, sub_key_5, key_all_attrs - {CHECK_MTIME}, value_all_attrs),
               (key, sub_key_6, key_all_attrs - {CHECK_OWNER} - {CHECK_GROUP} - {CHECK_PERM}, value_all_attrs)
               ]

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'WINDOWS_REGISTRY_3': test_regs[2],
               'WINDOWS_REGISTRY_4': test_regs[3],
               'WINDOWS_REGISTRY_5': test_regs[4],
               'WINDOWS_REGISTRY_6': test_regs[5]
               }

configurations_path = os.path.join(test_data_path, 'wazuh_check_all.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('key, subkey, arch, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, {'check_all_yes'}),
    (key, sub_key_2, KEY_WOW64_32KEY, {'check_all_yes'}),
    (key, sub_key_2, KEY_WOW64_64KEY, {'check_all_yes'})
])
def test_check_all_yes(key, subkey, arch, tags_to_apply,
                       get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test the functionality of `check_all` option when it's set to yes
    Example:
        <windows_registry check_all="yes">HKEY_SOME_KEY</windows_registry>
    Parameters
    ----------
    key: str
        Root key (HKEY_* constants)
    subkey: str
        Path of the key
    arch: int
        Architecture of the key
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, min_timeout=15,
                     options=REQUIRED_REG_KEY_ATTRIBUTES[CHECK_ALL],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, min_timeout=15,
                       options=REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL],
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


@pytest.mark.parametrize('key, subkey, arch, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, {'check_all_no'}),
    (key, sub_key_2, KEY_WOW64_32KEY, {'check_all_no'}),
    (key, sub_key_2, KEY_WOW64_64KEY, {'check_all_no'})
])
def test_check_all_no(key, subkey, arch, tags_to_apply,
                      get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test the functionality of `check_all` option when it's set to "no"
    Example:
        <windows_registry check_all="no">HKEY_SOME_KEY</windows_registry>
    Parameters
    ----------
    key: str
        Root key (HKEY_* constants)
    subkey: str
        Path of the key
    arch: int
        Architecture of the key
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, min_timeout=15, options=set(),
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     triggers_event_modified=False)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, min_timeout=15, options=set(),
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       triggers_event_modified=False)


@pytest.mark.parametrize('key, subkey, key_attr, value_attr', params_list)
def test_check_conjuction(key, subkey, key_attr, value_attr, get_configuration, configure_environment,
                          restart_syscheckd, wait_for_fim_start):
    """
    Test the behaviour disabling different check options over the same key with check_all enabled

    Example:
        check_all: "yes" check_size: "no" check_sum: "no"

    Parameters
    ----------
    key: str
        key of the directory (HKEY_* constants).
    subkey: str
        Path of the subkey.
    key_attr: set
        Set of options that are expected for key events
    value_attr: set
        Set of options that are expected for value events
    """
    check_apply_test({'check_all_conjuction'}, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=15, options=key_attr,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=15, options=value_attr,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
