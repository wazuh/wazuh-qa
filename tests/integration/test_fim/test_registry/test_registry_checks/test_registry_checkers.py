'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events generated contain only
       the 'check_' fields specified in the configuration when using the 'check_all' attribute along
       with other 'check_' attributes.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_checks

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
    - fim_registry_checks
'''
import os
import sys

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
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key', [key])
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
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the 'check_' specified in
                 the configuration. These checks are attributes indicating that a monitored registry entry has
                 been modified. For example, if 'check_all=yes' and 'check_sum=no' are set for the same entry,
                 'syscheck' must send an event containing every possible 'check_' except the checksums.
                 For this purpose, the test will monitor a registry key using the 'check_all' attribute in
                 conjunction with one or more 'check_' on the same key, having 'check_all' to 'yes' and the other
                 one to 'no'. Then it will make key/value operations inside it, and finally, finally, the test
                 will verify that the FIM events generated contain only the fields of the 'checks' specified for
                 the monitored keys/values.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: Path of the key that will be created under the root key.
        - arch:
            type: str
            brief: Architecture of the registry.
        - key_attr:
            type: set
            brief: Set of options that are expected for key events.
        - value_attr:
            type: set
            brief: Set of options that are expected for value events.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - triggers_modification:
            type: bool
            brief: Specify if the given options generate registry events.
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
        - Verify that the FIM events generated contain only the 'check_' fields specified in the configuration.

    input_description: Different test cases are contained in an external YAML file (wazuh_check_all.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. Those are
                       combined with the testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, min_timeout=global_parameters.default_timeout,
                     options=key_attrs, triggers_event_modified=triggers_modification, time_travel=True)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=value_attrs, triggers_event_modified=triggers_modification, time_travel=True)
