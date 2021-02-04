# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, registry_key_cud, CHECK_GROUP, \
                              CHECK_ALL, CHECK_MTIME, CHECK_OWNER, CHECK_SIZE, CHECK_SUM, KEY_WOW64_32KEY, \
                              KEY_WOW64_64KEY, REQUIRED_REG_KEY_ATTRIBUTES, REQUIRED_REG_VALUE_ATTRIBUTES, \
                              generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
subkey_1 = "SOFTWARE\\testkey1"
subkey_2 = "SOFTWARE\\testkey2"
key_name = "test_subkey"

recursion_key = "some_key\\sub_key\\sub_sub_key"

# Checkers

key_all_attrs = REQUIRED_REG_KEY_ATTRIBUTES[CHECK_ALL]
value_all_attrs = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL]

checkers_key_case1 = key_all_attrs.union(value_all_attrs)
checkers_subkey_case1 = (key_all_attrs - {CHECK_GROUP} - {CHECK_OWNER}).union((value_all_attrs - {CHECK_SIZE}))

checkers_key_case2 = {CHECK_MTIME, CHECK_SIZE}.union(REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM])
checkers_subkey_case2 = key_all_attrs.union(value_all_attrs)

tag = 'insert_a_random_tag'

test_regs = [os.path.join(key, subkey_1),
             os.path.join(key, subkey_2),
             os.path.join(key, subkey_1, key_name),
             os.path.join(key, subkey_2, key_name),
             os.path.join(key, subkey_1),
             os.path.join(key, os.path.join(subkey_1, recursion_key, key_name)),
             os.path.join(key, subkey_2),
             os.path.join(key, os.path.join(subkey_2, recursion_key, key_name))
             ]

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'SUBKEY_1': test_regs[2],
               'SUBKEY_2': test_regs[3],
               'RESTRICT_KEY': "test_",
               'RESTRICT_VALUE': "test_value",
               'TAG_1': tag,
               'REGISTRY_RECURSION_1': test_regs[4],
               'RECURSION_SUBKEY_1': test_regs[5],
               'RECURSION_LEVEL_1': 3,
               'REGISTRY_RECURSION_2': test_regs[6],
               'RECURSION_SUBKEY_2': test_regs[7],
               'RECURSION_LEVEL_2': 3,
               }

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_ambiguous_simple.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('key, sub_keys, is_key, name', [
                        (key, (subkey_1, os.path.join(subkey_1, key_name)), True, "onekey"),
                        (key, (subkey_2, os.path.join(subkey_2, key_name)), False, "other_value")
])
def test_ambiguous_restrict(key, sub_keys, is_key, name,
                            get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check restrict configuration events.

    Check if syscheck detects changes (add, modify, delete) of key/events depending on its restrict configuration.

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_keys: tuple
        Tuple where the first element is the path of a key that won't raise alerts due to the restrict and the
        second element is a key that will raise alerts.
    is_key: boolean
        Variable to distinguish if the restrict is for keys or for values.
    name: str
        String with the name of the value/key that will be created.
    """
    check_apply_test({"ambiguous_restrict"}, get_configuration['tags'])

    if is_key:
        registry_key_cud(key, sub_keys[0], wazuh_log_monitor, key_list=[name], arch=KEY_WOW64_64KEY,
                         triggers_event=False, time_travel=True, min_timeout=global_parameters.default_timeout)
        registry_key_cud(key, sub_keys[1], wazuh_log_monitor, key_list=[name], arch=KEY_WOW64_64KEY,
                         triggers_event=True, time_travel=True, min_timeout=global_parameters.default_timeout)
    else:
        registry_value_cud(key, sub_keys[0], wazuh_log_monitor, value_list=[name], arch=KEY_WOW64_64KEY,
                           triggers_event=False, time_travel=True, min_timeout=global_parameters.default_timeout)
        registry_value_cud(key, sub_keys[1], wazuh_log_monitor, value_list=[name],
                           triggers_event=True, time_travel=True, min_timeout=global_parameters.default_timeout)


@pytest.mark.parametrize('key, sub_keys, arch', [
                        (key, (subkey_1, os.path.join(subkey_1, key_name)), KEY_WOW64_64KEY),
                        (key, (subkey_2, os.path.join(subkey_2, key_name)), KEY_WOW64_64KEY),
                        (key, (subkey_2, os.path.join(subkey_2, key_name)), KEY_WOW64_32KEY)
])
def test_ambiguous_tags(key, sub_keys, arch,
                        get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """Check if syscheck detects the event property 'tags' for each event.

    This test validates both situations, making sure that if tags='no', there won't be a
    tags event property.

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_keys: tuple
        Tuple where the first element is the path of a key that will have the tag attribute
        and the second won't have the tag attribute.
    arch: int
        Architecture of the key.
    """

    def tag_validator(event):
        """Validate tags event property exists in the event."""
        assert tag == event['data']['tags'], 'Defined_tags are not equal'

    def no_tag_validator(event):
        """Validate tags event property does not exist in the event."""
        assert 'tags' not in event['data'].keys(), "'Tags' attribute found in event"

    check_apply_test({"ambiguous_tag"}, get_configuration['tags'])

    registry_key_cud(key, sub_keys[0], wazuh_log_monitor, arch=arch, time_travel=True,
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[tag_validator])

    registry_key_cud(key, sub_keys[1], wazuh_log_monitor, arch=arch, time_travel=True,
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[no_tag_validator])


@pytest.mark.parametrize('key, subkey, arch', [
                        (key, os.path.join(subkey_1, recursion_key), KEY_WOW64_64KEY),
                        (key, os.path.join(subkey_2, recursion_key), KEY_WOW64_64KEY),
                        (key, os.path.join(subkey_2, recursion_key), KEY_WOW64_32KEY)
])
def test_ambiguous_recursion(key, subkey, arch,
                             get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if syscheck detects the event property 'tags' for each event.

    This test validates both situations, making sure that if tags='no', there won't be a
    tags event property.

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_keys: str
        Path of the subkey that will be used for the test (must have a higher recursion level than the configured key).
        Example:
        <windows_registry recursion_level="2">HKLM//some_key</windows_registry>
        subkey = HKLM//some_key//1//2//3

    arch: int
        Architecture of the key.
    """
    expected_recursion_key = os.path.join(subkey, key_name)
    check_apply_test({"ambiguous_recursion"}, get_configuration['tags'])

    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch,
                     time_travel=True, triggers_event=False, min_timeout=global_parameters.default_timeout)

    registry_key_cud(key, expected_recursion_key, wazuh_log_monitor, arch=arch,
                     time_travel=True, triggers_event=True, min_timeout=global_parameters.default_timeout)

    registry_value_cud(key, expected_recursion_key, wazuh_log_monitor, arch=arch,
                       time_travel=True, triggers_event=True, min_timeout=global_parameters.default_timeout)


@pytest.mark.parametrize('key, subkey, key_checkers, subkey_checkers', [
                        (key, (subkey_1, os.path.join(subkey_1, key_name)), checkers_key_case1, checkers_subkey_case1),
                        (key, (subkey_2, os.path.join(subkey_2, key_name)), checkers_key_case2, checkers_subkey_case2)
])
def test_ambiguous_checks(key, subkey, key_checkers, subkey_checkers,
                          get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if syscheck detects the event property 'tags' for each event.

    This test validates both situations, making sure that if tags='no', there won't be a
    tags event property.

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_keys: tuple
        Tuple where ther first element is the configured key and the second is the configured subkey.
    arch: int
        Architecture of the key.
    """
    check_apply_test({"ambiguous_checks"}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey[0], wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                     options=key_checkers, time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry values.
    registry_value_cud(key, subkey[0], wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=key_checkers, time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry keys.
    registry_key_cud(key, subkey[1], wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                     options=subkey_checkers, time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry values.
    registry_value_cud(key, subkey[1], wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=subkey_checkers, time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
