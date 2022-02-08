'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM manages properly 'diff' folders
       and files when removing a monitored key/value or the 'report_changes' option is disabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#windows-registry
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_report_changes
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, check_time_travel, delete_registry, detect_initial_scan, \
    registry_value_cud, KEY_WOW64_32KEY, KEY_WOW64_64KEY, registry_parser, generate_params, \
    create_registry, modify_registry_value, calculate_registry_diff_paths, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test, set_section_wazuh_conf
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import restart_wazuh_with_new_conf

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

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
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
    '''
    description: Check if the 'wazuh-syscheckd' daemon creates a 'diff' file when a modification is made on
                 a monitored value and deletes that 'diff' file when it is deleted. This test also checks
                 that a 'diff' folder of a monitored key is removed when that key is deleted. For this purpose,
                 the test will monitor a key and make value operations inside it. Then, it will check if the
                 'diff' file has been created/deleted if the 'report_changes' option is enabled, and vice versa.
                 Finally, the test will remove the monitored key and verify that the 'diff' folder has been deleted.

    wazuh_min_version: 4.2.0

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: The registry key being monitored by syscheck.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_name:
            type: str
            brief: Name of the testing value that will be created
        - enabled:
            type: bool
            brief: True if the 'report_changes' option is enabled. False otherwise.
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM adds/removes a 'diff' file when modifying/deleting the corresponding value,
          and the 'report_changes' option is enabled.
        - Verify that FIM removes the 'diff' file of a related value when disabling the 'report_changes' option.
        - Verify that FIM removes the 'diff' folder when removing the related key.

    input_description: A test case (test_report_changes) is contained in external YAML file
                       (wazuh_registry_report_changes.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the testing registry keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
def test_report_changes_after_restart(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon removes the 'diff' directories when disabling
                 the 'report_changes' option and Wazuh is restarted. For this purpose, the test
                 will monitor two keys and make value operations inside them. Then, it will check if
                 the related 'diff' folders have been created. After this, it will apply a new main
                 configuration with the 'report_changes' disabled and restart Wazuh. Finally, the test
                 will verify that the 'diff' folders have been deleted.

    wazuh_min_version: 4.2.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM adds the 'diff' folders when the testing keys are created.
        - Verify that FIM deletes the 'diff' folders when disabling the 'report_changes' option
          and Wazuh is restarted.

    input_description: A test case (test_delete_after_restart) is contained in external YAML file
                       (wazuh_registry_report_changes.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
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
