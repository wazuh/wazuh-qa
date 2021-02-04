# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, check_time_travel, delete_registry, detect_initial_scan, \
                              registry_value_cud, KEY_WOW64_32KEY, KEY_WOW64_64KEY, registry_parser, generate_params, \
                              create_registry, modify_registry_value, calculate_registry_diff_paths, REG_SZ
from wazuh_testing.tools.services import restart_wazuh_with_new_conf

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test, set_section_wazuh_conf
from wazuh_testing.tools.monitoring import FileMonitor
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

conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'REPORT_CHANGES_1': 'yes',
               'REPORT_CHANGES_2': 'yes'}

configurations_path = os.path.join(test_data_path, 'wazuh_registry_report_changes.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Functions


def reload_new_conf(report_value, reg1, reg2):
    """"
    Return a new ossec configuration with a changed report_value

    Parameters
    ----------
    report_value: str
        Value that will be used for the report_changes option.
    reg1: str
        Registry path that will be written in the configuration for WINDOWS_REGISTRY_1.
    reg2: str
        Registry path that will be written in the configuration for WINDOWS_REGISTRY_2.
    """
    new_conf_params = {'WINDOWS_REGISTRY_1': reg1,
                       'WINDOWS_REGISTRY_2': reg2,
                       'REPORT_CHANGES_1': report_value,
                       'REPORT_CHANGES_2': report_value}

    conf_params, conf_metadata = generate_params(extra_params=new_conf_params, modes=['scheduled'])
    new_conf = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)
    # Load the third configuration in the yaml
    restart_wazuh_with_new_conf(set_section_wazuh_conf(new_conf[2].get('sections')))
    # Wait for FIM scan to finish
    detect_initial_scan(wazuh_log_monitor)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('key, subkey, arch, value_name, enabled, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", True, {'test_report_changes'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", True, {'test_report_changes'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", True, {'test_report_changes'}),
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", False, {'test_duplicate_report'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", True, {'test_duplicate_report'})
])
def test_report_when_deleted_key(key, subkey, arch, value_name, enabled, tags_to_apply,
                                 get_configuration, configure_environment, restart_syscheckd,
                                 wait_for_fim_start):
    """
    Check that the diff files are generated when there is a modification in a value and these files are deleted when
    the value is deleted.

    It also checks that the diff folder of the key is deleted when the key is deleted.

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
    enabled: boolean
        True if report_changes is enabled
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    vals_after_update = None
    vals_after_delete = None

    folder_path, diff_file = calculate_registry_diff_paths(key, subkey, arch, value_name)

    def report_changes_diff_file_validator(unused_param):
        """
        Validator that checks if the files are created.
        """
        assert os.path.exists(diff_file), f'{diff_file} does not exist'

    def report_changes_removed_diff_file_validator(unused_param):
        """
        Validator that checks if the files are removed when the values are removed.
        """
        assert not os.path.exists(diff_file), f'{diff_file} does exist'

    if enabled:
        vals_after_update = [report_changes_diff_file_validator]
        vals_after_delete = [report_changes_removed_diff_file_validator]
    else:
        vals_after_update = [report_changes_removed_diff_file_validator]
        vals_after_delete = [report_changes_removed_diff_file_validator]

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list={value_name: "some content"},
                       time_travel=True,
                       min_timeout=global_parameters.default_timeout,
                       validators_after_update=vals_after_update,
                       validators_after_delete=vals_after_delete)

    delete_registry(registry_parser[key], subkey, arch)

    assert not os.path.exists(folder_path), f'{folder_path} exists'


def test_report_changes_after_restart(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if diff directories are removed after disabling report_changes and Wazuh is restarted.
    """
    check_apply_test({'test_delete_after_restart'}, get_configuration['tags'])
    value_name = 'random_value'

    folder_path_key1, diff_file_key_1 = calculate_registry_diff_paths(key, sub_key_1, KEY_WOW64_64KEY, value_name)
    folder_path_key2, diff_file_key_2 = calculate_registry_diff_paths(key, sub_key_1, KEY_WOW64_64KEY, value_name)

    # Open key
    key1_h = create_registry(registry_parser[key], sub_key_1, KEY_WOW64_64KEY)
    key2_h = create_registry(registry_parser[key], sub_key_2, KEY_WOW64_64KEY)

    # Modify the registry
    modify_registry_value(key1_h, value_name, REG_SZ, "some_content")
    modify_registry_value(key2_h, value_name, REG_SZ, "some_content")

    # Travel to future
    check_time_travel(True, monitor=wazuh_log_monitor)

    assert os.path.exists(diff_file_key_1), f'{diff_file_key_1} does not exists'
    assert os.path.exists(diff_file_key_2), f'{diff_file_key_2} does not exists'

    reload_new_conf('no', test_regs[0], test_regs[1])

    assert not os.path.exists(folder_path_key1), f'{folder_path_key1} does exists'
    assert not os.path.exists(folder_path_key2), f'{folder_path_key2} does exists'
