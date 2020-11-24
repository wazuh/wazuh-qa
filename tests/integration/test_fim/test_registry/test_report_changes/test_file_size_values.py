# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from hashlib import sha1
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from test_fim.test_files.test_report_changes.common import generate_string

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs


# Configurations

p, m = generate_params(modes=['scheduled'], extra_params={'WINDOWS_REGISTRY_1': reg1,
                                                          'WINDOWS_REGISTRY_2': reg2,
                                                          'FILE_SIZE_ENABLED': 'yes',
                                                          'FILE_SIZE_LIMIT': '2KB',
                                                          'DISK_QUOTA_ENABLED': 'no',
                                                          'DISK_QUOTA_LIMIT': '4KB'})

configurations_path = os.path.join(test_data_path, 'wazuh_registry_report_changes.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('size', [
    (512),
    (10240)
])
@pytest.mark.parametrize('key, subkey, arch, value_name, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", {'test_limits'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", {'test_limits'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", {'test_limits'})
])
def test_file_size_values(key, subkey, arch, value_name, tags_to_apply, size,
                          get_configuration, configure_environment, restart_syscheckd,
                          wait_for_fim_start):
    """
    Check that no events are sent when the file_size exceeded

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
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    size : int
        Size of the content to write in value
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    value_content = generate_string(size, '0')
    values = {value_name: value_content}

    def report_changes_validator_no_diff(event):
        """Validate content_changes attribute exists in the event"""
        for value in values:
            folder_key = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_key,
                                     sha1(value.encode()).hexdigest(), 'last-entry.gz')

            assert not os.path.exists(diff_file), '{diff_file} exist, it shouldn\'t'
            assert event['data'].get('content_changes') is None, 'content_changes isn\'t empty'

    def report_changes_validator_diff(event):
        """Validate content_changes attribute exists in the event"""
        for value in values:
            folder_key = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_key,
                                     sha1(value.encode()).hexdigest(), 'last-entry.gz')

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    if size > 2048:
        callback_test = report_changes_validator_no_diff
    else:
        callback_test = report_changes_validator_diff

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=values,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[callback_test])
