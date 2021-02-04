# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import CHECK_GROUP, CHECK_MTIME, CHECK_OWNER, CHECK_PERM, \
    CHECK_SHA256SUM, CHECK_SIZE, CHECK_MD5SUM, CHECK_SHA1SUM, CHECK_SUM, CHECK_ALL, \
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
value_attrs = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL] - {CHECK_TYPE} - {CHECK_SIZE}

attrs_key_1, attrs_value_1 = key_all_attrs, value_all_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]
attrs_key_2, attrs_value_2 = key_all_attrs, value_all_attrs - {CHECK_SHA256SUM}
attrs_key_3, attrs_value_3 = key_all_attrs, value_all_attrs - {CHECK_TYPE}
attrs_key_4, attrs_value_4 = key_all_attrs, value_all_attrs - {CHECK_SIZE}
attrs_key_5, attrs_value_5 = key_all_attrs - {CHECK_MTIME}, value_all_attrs
attrs_key_6, attrs_value_6 = key_all_attrs - {CHECK_OWNER} - {CHECK_GROUP} - {CHECK_PERM}, value_all_attrs

attrs_value_sum_all_1 = value_all_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]
attrs_value_sum_all_2 = value_all_attrs - {CHECK_MD5SUM} - {CHECK_SHA256SUM}
attrs_value_sum_all_3 = value_all_attrs - {CHECK_MD5SUM} - {CHECK_SHA1SUM}
attrs_value_sum_all_4 = value_all_attrs - {CHECK_SHA256SUM} - {CHECK_SHA1SUM}

attrs_value_sum_1 = value_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]
attrs_value_sum_2 = value_attrs - {CHECK_MD5SUM} - {CHECK_SHA256SUM}
attrs_value_sum_3 = value_attrs - {CHECK_MD5SUM} - {CHECK_SHA1SUM}
attrs_value_sum_4 = value_attrs - {CHECK_SHA256SUM} - {CHECK_SHA1SUM}

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


# Test
@pytest.mark.parametrize('key', [
    key
])
@pytest.mark.parametrize('subkey, arch, key_attrs, value_attrs, tags_to_apply, triggers_modification', [
    (sub_key_1, KEY_WOW64_64KEY, key_all_attrs, value_all_attrs, {'check_all_yes'}, True),
    (sub_key_2, KEY_WOW64_32KEY, key_all_attrs, value_all_attrs, {'check_all_yes'}, True),
    (sub_key_2, KEY_WOW64_64KEY, key_all_attrs, value_all_attrs, {'check_all_yes'}, True),
    (sub_key_1, KEY_WOW64_64KEY, set(), set(), {'check_all_no'}, False),
    (sub_key_2, KEY_WOW64_32KEY, set(), set(), {'check_all_no'}, False),
    (sub_key_2, KEY_WOW64_64KEY, set(), set(), {'check_all_no'}, False),
    (sub_key_1, KEY_WOW64_64KEY, attrs_key_1, attrs_value_1, {'check_all_conjuction'}, True),
    (sub_key_2, KEY_WOW64_64KEY, attrs_key_2, attrs_value_2, {'check_all_conjuction'}, True),
    (sub_key_3, KEY_WOW64_64KEY, attrs_key_3, attrs_value_3, {'check_all_conjuction'}, True),
    (sub_key_4, KEY_WOW64_64KEY, attrs_key_4, attrs_value_4, {'check_all_conjuction'}, True),
    (sub_key_5, KEY_WOW64_64KEY, attrs_key_5, attrs_value_5, {'check_all_conjuction'}, True),
    (sub_key_6, KEY_WOW64_64KEY, attrs_key_6, attrs_value_6, {'check_all_conjuction'}, True),
    (sub_key_1, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_all_1, {'test_checksum_all'}, True),
    (sub_key_2, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_all_2, {'test_checksum_all'}, True),
    (sub_key_3, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_all_3, {'test_checksum_all'}, True),
    (sub_key_4, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_all_4, {'test_checksum_all'}, True),
    (sub_key_1, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_1, {'test_checksum'}, True),
    (sub_key_2, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_2, {'test_checksum'}, True),
    (sub_key_3, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_3, {'test_checksum'}, True),
    (sub_key_4, KEY_WOW64_64KEY, key_all_attrs, attrs_value_sum_4, {'test_checksum'}, True)
])
def test_checkers(key, subkey, arch, key_attrs, value_attrs, tags_to_apply, triggers_modification,
                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test the functionality of `check_all` option is activated/desactivated alone and together with other
    `check_*` options.

    Example:
        <windows_registry check_all="yes">HKEY_SOME_KEY</windows_registry>.
    Parameters
    ----------
    key: str
        Root key (HKEY_* constants).
    subkey: str
        Path of the key.
    arch: int
        Architecture of the key.
    key_attrs: set
        Attributes for the key events.
    value_attrs: set
        Attributes for the value events.
    tags_to_apply: set
        Configuration that will be applied for every case.
    triggers_modification: boolean
        True if the given attributes trigger modification events.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, min_timeout=global_parameters.default_timeout,
                     options=key_attrs, triggers_event_modified=triggers_modification, time_travel=True)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=value_attrs, triggers_event_modified=triggers_modification, time_travel=True)
