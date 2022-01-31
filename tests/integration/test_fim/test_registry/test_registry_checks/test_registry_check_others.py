'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM events generated
       contain only the 'check_' fields specified in the configuration when using the 'check_'
       attributes individually and use the 'check_all=no' attribute.
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
from wazuh_testing.fim import CHECK_MTIME, CHECK_PERM, \
    CHECK_SIZE, CHECK_SUM, CHECK_ALL, \
    CHECK_TYPE, LOG_FILE_PATH, REQUIRED_REG_VALUE_ATTRIBUTES, \
    REQUIRED_REG_KEY_ATTRIBUTES, generate_params, registry_value_cud, \
    registry_key_cud
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\testkey1"
sub_key_2 = "SOFTWARE\\testkey2"
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

params_list = [(key, sub_key_1, key_all_attrs, {CHECK_SUM}, True, True),
               (key, sub_key_2, key_all_attrs, {CHECK_SIZE}, True, True),
               (key, sub_key_3, key_all_attrs, {CHECK_TYPE}, True, False),
               (key, sub_key_4, set(), value_all_attrs, False, True),
               (key, sub_key_5, key_all_attrs - {CHECK_PERM}, value_all_attrs, True, True),
               (key, sub_key_6, {CHECK_MTIME, CHECK_PERM}, value_all_attrs, True, True)
               ]
#               key, subkey,    key attrs                value_attrs,     key_mod, value_mod
# Configurations

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'WINDOWS_REGISTRY_3': test_regs[2],
               'WINDOWS_REGISTRY_4': test_regs[3],
               'WINDOWS_REGISTRY_5': test_regs[4],
               'WINDOWS_REGISTRY_6': test_regs[5]
               }

configurations_path = os.path.join(test_data_path, 'wazuh_check_others.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.skipif(sys.platform == 'win32', reason="Blocked by wazuh/wazuh-qa#2174 - Refactor required")
@pytest.mark.parametrize('key, subkey, key_attr, value_attr, triggers_key_modification, triggers_value_modification',
                         params_list)
def test_check_others(key, subkey, key_attr, value_attr, triggers_key_modification, triggers_value_modification,
                      get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the 'check_' specified in
                 the configuration. These checks are attributes indicating that a monitored registry entry has
                 been modified. For example, if 'check_all=no' and 'check_sum=yes' are set for the same entry,
                 'syscheck' must send an event containing only the checksums.
                 For this purpose, the test will monitor a registry key using the 'check_all=no' attribute
                 (in order to avoid using the default 'check_all' configuration) in conjunction with several
                 'check_' on the same key. Then it will make key/value operations inside it, and finally,
                 the test will verify that FIM events generated contain only the fields of the 'check_' specified
                 for the monitored keys/values.

    wazuh_min_version: 4.2.0

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: Path of the key that will be created under the root key.
        - key_attr:
            type: set
            brief: Set of options that are expected for key events.
        - value_attr:
            type: set
            brief: Set of options that are expected for value events.
        - triggers_key_modification:
            type: bool
            brief: Specify if the given options generate key events.
        - triggers_value_modification:
            type: bool
            brief: Specify if the given options generate value events.
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

    input_description: A test case (test_others) is contained in an external YAML file
                       (wazuh_check_others.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'test_others'}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, options=key_attr,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     triggers_event_modified=triggers_key_modification)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=value_attr, time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       triggers_event_modified=triggers_value_modification)
