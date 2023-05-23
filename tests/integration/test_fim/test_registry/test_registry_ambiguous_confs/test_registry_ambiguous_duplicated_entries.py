'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM watches selected
       files and triggering alerts when these files are modified. All these tests will be performed
       using complex paths and ambiguous configurations, such as keys and subkeys with opposite
       monitoring settings. In particular, it will verify that duplicate events are not generated
       when multiple configurations are used to monitor the same registry key.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_ambiguous_confs

targets:
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

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_ambiguous_confs
'''
import os
import sys
from hashlib import sha1

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, registry_key_cud, \
    generate_params, CHECK_GROUP, CHECK_TYPE, \
    CHECK_ALL, CHECK_MTIME, CHECK_SIZE, CHECK_SUM, KEY_WOW64_32KEY, \
    KEY_WOW64_64KEY, REQUIRED_REG_KEY_ATTRIBUTES, REQUIRED_REG_VALUE_ATTRIBUTES
from wazuh_testing.tools import WAZUH_PATH
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
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key', [key])
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
    '''
    description: Check if the 'wazuh-syscheckd' daemon uses the last entry when setting multiple ones with
                 the same key path in the configuration. For this purpose, the test will monitor a registry
                 key that is duplicated using diferent settings in the configuration, and make key/value
                 operations inside it. Finally, the test will verify that FIM events are only generated from
                 the last entry detected.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - arch:
            type: str
            brief: Architecture of the registry.
        - key_list:
            type: list
            brief: List with the name of the keys that will be used to make CUD operations.
        - value_list:
            type: list
            brief: List with the name of the values that will be used to make CUD operations.
        - checkers:
            type: set
            brief: Set of 'check_' fields that are expected.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that FIM events are generated from only one entry of the configuration.

    input_description: Diferent test cases are contained in an external YAML file (wazuh_duplicated_entries.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. These are combined
                       with the testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test registry keys.
    if key_list is not None:
        registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, key_list=key_list, options=checkers,
                         min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=True)

    if value_list is not None:
        registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=value_list, options=checkers,
                           min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=True)


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key', [key])
@pytest.mark.parametrize('subkey, arch, value_list, tags_to_apply, report_changes', [
    (subkey_1, KEY_WOW64_64KEY, ['test_value'], {'duplicate_report_entries'}, True),
    (subkey_2, KEY_WOW64_64KEY, ['test_value'], {'duplicate_report_entries'}, False),
])
def test_duplicate_entries_rc(key, subkey, arch, value_list, tags_to_apply, report_changes,
                              get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon uses the last entry when setting multiple ones
                 using the same key path and the 'report_changes' attribute in the configuration.
                 For this purpose, the test will monitor a registry key that is duplicated using a different
                 value for the 'report_changes' attribute in the configuration, and make value operations
                 inside it. Finally, the test will verify that FIM events generated include the value changes
                 when this option is enabled in the last entry of the configuration.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_list:
            type: list
            brief: List with the name of the values that will be used to make CUD operations.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - report_changes:
            type: bool
            brief: True if the key is configured to report changes. False otherwise.
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
        - Verify that FIM events generated include in its 'content_changes' field the changes made
          in the monitored key when 'report_changes == yes'.
        - Verify that a 'diff' file is created when 'report_changes == yes' and changes are made
          on the monitored value.

    input_description: A test case (duplicate_report_entries) is contained in an external YAML file
                       (wazuh_duplicated_entries.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry keys
                       to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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
