# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import CHECK_OWNER, LOG_FILE_PATH, registry_value_cud, registry_key_cud, \
                              generate_params, CHECK_SUM, CHECK_TYPE, CHECK_GROUP, \
                              CHECK_ALL, CHECK_MTIME, CHECK_SIZE, \
                              REQUIRED_REG_KEY_ATTRIBUTES, REQUIRED_REG_VALUE_ATTRIBUTES
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

from wazuh_testing.tools import WAZUH_PATH
from hashlib import sha1

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
registry = "SOFTWARE\\random_key"

tag_1 = "tag_1"
tag_2 = "tag_2"
tag_3 = "tag_3"

subkey_1 = os.path.join(registry, "subkey_1")
subkey_2 = os.path.join(subkey_1, "subkey_2")
subkey_3 = os.path.join(subkey_2, "subkey_3")

test_regs = [os.path.join(key, registry),
             os.path.join(key, subkey_1),
             os.path.join(key, subkey_2),
             os.path.join(key, subkey_3),
             ]

confs_params = {'KEY1': test_regs[0],
                'SUBKEY_1': test_regs[1],
                'SUBKEY_2': test_regs[2],
                'SUBKEY_3': test_regs[3],
                'TAG_1': tag_1,
                'TAG_2': tag_2,
                'TAG_3': tag_3
                }


key_all_attrs = REQUIRED_REG_KEY_ATTRIBUTES[CHECK_ALL].union(REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL])

checkers_key = key_all_attrs
checkers_subkey1 = {CHECK_TYPE, CHECK_MTIME, CHECK_SIZE}
checkers_subkey2 = key_all_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]
checkers_subkey3 = key_all_attrs - {CHECK_GROUP, CHECK_OWNER}

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_complex_entries.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
p, m = generate_params(extra_params=confs_params, modes=['scheduled'])

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
@pytest.mark.parametrize('subkey, key_checkers', [
                        (registry, checkers_key),
                        (subkey_1, checkers_subkey1),
                        (subkey_2, checkers_subkey2),
                        (subkey_3, checkers_subkey3)
])
def test_ambiguous_complex_checks(key, subkey, key_checkers,
                                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if the events of every configured key has the proper check attributes.

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_key: str
        Path of the configured key.
    key_checkers: set
        Set of checks that are expected.
    """
    check_apply_test({"complex_checks"}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                     options=key_checkers, time_travel=True)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=key_checkers, time_travel=True)


@pytest.mark.parametrize('key', [
    key
])
@pytest.mark.parametrize('subkey, value_list, report,', [
                        (registry, ['test_value'], True),
                        (subkey_1, ['test_value'], False),
                        (subkey_2, ['test_value'], False),
                        (subkey_3, ['test_value'], True)
])
def test_ambiguous_report_changes(key, subkey, value_list, report,
                                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if report changes works properly for every configured entry

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_key: str
        Path of the configured key.
    value_list: list
        List with the name of the values that will be used in the cud operation.
    report: boolean
        True if the key is configured with report changes.
    """
    check_apply_test({'complex_report_changes'}, get_configuration['tags'])

    validator_after_update = None

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for value in value_list:
            folder_str = "{} {}".format("[x64]", sha1(os.path.join(key, subkey).encode()).hexdigest())
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_str,
                                     sha1(value.encode()).hexdigest())

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    if report:
        validator_after_update = [report_changes_validator]
    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       value_list=value_list, time_travel=True, validators_after_update=validator_after_update)


@pytest.mark.parametrize('key', [
    key
])
@pytest.mark.parametrize('subkey, tag', [
                        (registry, None),
                        (subkey_1, tag_1),
                        (subkey_2, tag_2),
                        (subkey_3, tag_3)
])
def test_ambiguous_report_tags(key, subkey, tag,
                               get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if syscheck detects the event property 'tags' for each configured entry.

    This test validates both situations, making sure that if tags='no', there won't be a
    tags event property.

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants).
    sub_key: str
        Path of the configured key.
    tag: str
        Tag that is configured for each entry. If None, the entry isn't configured with a tag.
    """
    check_apply_test({'complex_tags'}, get_configuration['tags'])

    def no_tag_validator(event):
        """Validate tags event property does not exist in the event."""
        assert 'tags' not in event['data'].keys(), "'Tags' attribute found in event"

    def tag_validator(event):
        """Validate tags event property exists in the event."""
        assert tag == event['data']['tags'], 'Defined_tags are not equal'

    validator_after_create = [no_tag_validator]
    validator_after_update = [no_tag_validator]
    validator_after_delete = [no_tag_validator]

    if tag is not None:
        validator_after_create = [tag_validator]
        validator_after_update = [tag_validator]
        validator_after_delete = [tag_validator]

    # Test registry values.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                     time_travel=True, validators_after_create=validator_after_create,
                     validators_after_update=validator_after_update, validators_after_delete=validator_after_delete
                     )

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       time_travel=True, validators_after_create=validator_after_create,
                       validators_after_update=validator_after_update, validators_after_delete=validator_after_delete
                       )
