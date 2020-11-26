# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from hashlib import sha1
from time import sleep

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"
no_diff_value = "nodiff_value"
value_sregex = "nodiff_value$"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs


# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'VALUE_1': os.path.join(reg1, no_diff_value),
               'VALUE_2': os.path.join(reg2, no_diff_value),
               'SREGEX_1': value_sregex,
               'SREGEX_2': value_sregex}

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('key, subkey, arch, value_name, truncated, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_str'}),
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", False, {'no_diff_str'}),
    (key, sub_key_1, KEY_WOW64_32KEY, no_diff_value, True, {'no_diff_str'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", False, {'no_diff_str'}),
    (key, sub_key_2, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_str'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", False, {'no_diff_str'})

])
def test_no_diff_str(key, subkey, arch, value_name, truncated, tags_to_apply,
                     get_configuration, configure_environment, restart_syscheckd,
                     wait_for_fim_start):
    """
    Check the only values detected are those matching the restrict using the value path.

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        path of the registry.
    arch : str
        Architecture of the registry.
    value_name : str
        Name of the value that will be created
    truncated : bool
        True if an event must be generated, False otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    values = {value_name: "some content"}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for value in values:
            folder_str = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_str,
                                     sha1(value.encode()).hexdigest())

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if truncated:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=values,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[report_changes_validator, no_diff_validator])
    sleep(0.5)


@pytest.mark.parametrize('key, subkey, arch, value_name, truncated, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_regex'}),
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", False, {'no_diff_regex'}),
    (key, sub_key_1, KEY_WOW64_32KEY, no_diff_value, True, {'no_diff_regex'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", False, {'no_diff_regex'}),
    (key, sub_key_2, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_regex'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", False, {'no_diff_regex'})
])
def test_no_diff_regex(key, subkey, arch, value_name, truncated, tags_to_apply,
                       get_configuration, configure_environment, restart_syscheckd,
                       wait_for_fim_start):
    """
    Check the only files detected are those matching the restrict regex.

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        path of the registry.
    arch : str
        Architecture of the registry.
    value_name : str
        Name of the value that will be created
    truncated : bool
        True if an event must be generated, False otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    values = {value_name: "some content"}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for value in values:
            folder_str = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())

            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_str,
                                     sha1(value.encode()).hexdigest())

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if truncated:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'
    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=values,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[report_changes_validator, no_diff_validator])
    # Avoid overlapping of events
    sleep(0.5)
