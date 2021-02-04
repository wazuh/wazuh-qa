# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os

import pytest
from hashlib import sha1

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, registry_key_cud, \
                              generate_params, CHECK_GROUP, CHECK_TYPE, \
                              CHECK_ALL, CHECK_MTIME, CHECK_SIZE, CHECK_SUM, KEY_WOW64_32KEY, \
                              KEY_WOW64_64KEY, REQUIRED_REG_KEY_ATTRIBUTES, REQUIRED_REG_VALUE_ATTRIBUTES
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
subkey_1 = "SOFTWARE\\test_key1"
subkey_2 = "SOFTWARE\\test_key2"
subkey_3 = "SOFTWARE\\test_key3"
subkey_4 = "SOFTWARE\\test_key4"

test_regs = [os.path.join(key, subkey_1),
             os.path.join(key, subkey_2),
             os.path.join(key, subkey_3),
             os.path.join(key, subkey_4)
             ]

registry_list = "{},{},{},{}".format(test_regs[0], test_regs[1], test_regs[2], test_regs[3])

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'WINDOWS_REGISTRY_LIST': registry_list,
               'RESTRICT_1': "overwritten_restrict$",
               'RESTRICT_2': "restrict_test_|test_key"
               }


key_all_attrs = REQUIRED_REG_KEY_ATTRIBUTES[CHECK_ALL].union(REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL])

checkers_key_1 = key_all_attrs - {CHECK_GROUP, CHECK_TYPE}
checkers_key_2 = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM].union({CHECK_MTIME, CHECK_TYPE, CHECK_SIZE})

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_duplicated_entries.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
@pytest.mark.parametrize('key', [
    key
])
@pytest.mark.parametrize('subkey, arch, key_list, value_list, checkers, tags_to_apply', [
    (subkey_1, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_entries'}),
    (subkey_2, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_entries'}),
    (subkey_2, KEY_WOW64_32KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_entries'}),
    (subkey_1, KEY_WOW64_64KEY, None, ['restrict_test_value'], key_all_attrs, {'duplicate_restrict_entries'}),
    (subkey_2, KEY_WOW64_64KEY, ['restrict_test_key'], None, key_all_attrs, {'duplicate_restrict_entries'}),
    (subkey_1, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_arch_entries'}),
    (subkey_1, KEY_WOW64_32KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_arch_entries'}),
    (subkey_2, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_arch_entries'}),
    (subkey_2, KEY_WOW64_32KEY, ['random_key'], ['test_value'], key_all_attrs, {'duplicate_arch_entries'}),
    (subkey_1, KEY_WOW64_64KEY, ['restrict_test_key'], ['restrict_test_value'], checkers_key_1, {'complex_entries'}),
    (subkey_2, KEY_WOW64_64KEY, ['random_key'], ['random_value'], checkers_key_2, {'complex_entries'}),
    (subkey_2, KEY_WOW64_32KEY, ['random_key'], ['random_value'], checkers_key_2, {'complex_entries'}),
    (subkey_1, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'single_registry_and_list'}),
    (subkey_2, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'single_registry_and_list'}),
    (subkey_3, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'single_registry_and_list'}),
    (subkey_4, KEY_WOW64_64KEY, ['random_key'], ['test_value'], key_all_attrs, {'single_registry_and_list'}),

])
def test_duplicate_entries(key, subkey, arch, key_list, value_list, checkers, tags_to_apply,
                           get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check that duplicate antries are overwritten by the last entry.

    Parameters
    ----------
    key: str
        Root key (HKEY_*)
    subkey: str
        path of the registry where the test will be executed.
    arch: str
        Architecture of the registry.
    key_list: list
        List with the name of the keys that will be used for cud. If None, registry_key_cud won't be executed.
    value_list: list
        List with the name of the values that will be used for cud. If None, registry_value_cud won't be executed.
    checkers: set
        Set with the checkers that are expected in the events.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test registry keys.
    if key_list is not None:
        registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, key_list=key_list, options=checkers,
                         min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=True)

    if value_list is not None:
        registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=value_list, options=checkers,
                           min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=True)


@pytest.mark.parametrize('key', [
    key
])
@pytest.mark.parametrize('subkey, arch, value_list, tags_to_apply, report_changes', [
                        (subkey_1, KEY_WOW64_64KEY, ['test_value'], {'duplicate_report_entries'}, True),
                        (subkey_2, KEY_WOW64_64KEY, ['test_value'], {'duplicate_report_entries'}, False),
])
def test_duplicate_entries_rc(key, subkey, arch, value_list, tags_to_apply, report_changes,
                              get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check registry entries are overwritten when report changes is activated/deactivated.

    Parameters
    ----------
    key: str
        Root key (HKEY_* constants).
    subkey: str
        path of the registry where the test will be executed.
    arch: str
        Architecture of the registry.
    value_list: list
        List with the name of the values that will be used for cud.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        if not report_changes:
            return

        for value in value_list:
            folder_str = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_str,
                                     sha1(value.encode()).hexdigest())

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=value_list,
                       time_travel=True, min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[report_changes_validator])
