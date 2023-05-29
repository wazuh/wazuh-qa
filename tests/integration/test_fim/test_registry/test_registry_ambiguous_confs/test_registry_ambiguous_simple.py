'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM watches selected
       files and triggering alerts when these files are modified. All these tests will be performed
       using ambiguous configurations, such as keys and subkeys with opposite monitoring settings.
       In particular, it will verify that the 'restrict_*', 'tags', 'recursion_level', and 'check_'
       attributes work properly.
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
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, sub_keys, arch', [
    (key, (subkey_1, os.path.join(subkey_1, key_name)), KEY_WOW64_64KEY),
    (key, (subkey_2, os.path.join(subkey_2, key_name)), KEY_WOW64_64KEY),
    (key, (subkey_2, os.path.join(subkey_2, key_name)), KEY_WOW64_32KEY)
])
def test_ambiguous_tags(key, sub_keys, arch,
                        get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds, in the generated events, the tags specified in
                 the configuration. The 'tags' attribute allows adding tags to alerts for monitored registry
                 keys. For this purpose, the test will monitor a registry key using different tags in
                 key and subkey paths. Then it will make key operations inside that entry, and finally, the
                 test will verify that FIM events generated include only in its 'tags' field, the tags set
                 in the configuration for the monitored key paths or subpaths.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_keys:
            type: tuple
            brief: The first entry does not have the tag attribute, and the second one does.
        - arch:
            type: str
            brief: Architecture of the registry.
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
        - Verify that FIM events generated contain in its 'tags' field the tags specified
          in the configuration for the monitored registry keys.
        - Verify that FIM events generated do not contain the 'tags' field
          when the 'tag' attribute is not used.

    input_description: A test case (ambiguous_tag) is contained in an external YAML file
                       (wazuh_ambiguous_simple.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, subkey, arch', [
    (key, os.path.join(subkey_1, recursion_key), KEY_WOW64_64KEY),
    (key, os.path.join(subkey_2, recursion_key), KEY_WOW64_64KEY),
    (key, os.path.join(subkey_2, recursion_key), KEY_WOW64_32KEY)
])
def test_ambiguous_recursion(key, subkey, arch,
                             get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events for a registry key level defined
                 in the 'recursion_level' attribute. The 'recursion_level' attribute limits the maximum
                 level of recursion allowed. For this purpose, the test will monitor a registry key
                 with several levels of deep and make key/value operations inside it. Finally, it
                 will verify that only FIM events are generated up to the deep level specified.

    wazuh_min_version: 4.2.0

    tier: 2

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
        - Verify that FIM events are generated up to the specified registry key depth.

    input_description: A test case (ambiguous_recursion) is contained in an external YAML file
                       (wazuh_ambiguous_simple.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    expected_recursion_key = os.path.join(subkey, key_name)
    check_apply_test({"ambiguous_recursion"}, get_configuration['tags'])

    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch,
                     time_travel=True, triggers_event=False, min_timeout=global_parameters.default_timeout)

    registry_key_cud(key, expected_recursion_key, wazuh_log_monitor, arch=arch,
                     time_travel=True, triggers_event=True, min_timeout=global_parameters.default_timeout)

    registry_value_cud(key, expected_recursion_key, wazuh_log_monitor, arch=arch,
                       time_travel=True, triggers_event=True, min_timeout=global_parameters.default_timeout)


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, subkey, key_checkers, subkey_checkers', [
    (key, (subkey_1, os.path.join(subkey_1, key_name)), checkers_key_case1, checkers_subkey_case1),
    (key, (subkey_2, os.path.join(subkey_2, key_name)), checkers_key_case2, checkers_subkey_case2)
])
def test_ambiguous_checks(key, subkey, key_checkers, subkey_checkers,
                          get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds, in the generated events, the 'check_' fields
                 specified in the configuration. These checks are attributes indicating that a monitored
                 key has been modified. For this purpose, the test will monitor a registry key using
                 different 'check_' attributes in key and subkey paths. Then it will make key/value operations
                 inside that key, and finally, the test will verify that the FIM events generated include
                 only the 'check_' fields set in the configuration for the monitored key paths or subpaths.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: Path of the key that will be created under the root key.
        - key_checkers:
            type: str
            brief: Path of the key that will be created under the root key.
        - subkey_checkers:
            type: str
            brief: Path of the key that will be created under the root key.
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
        - Verify that FIM events generated contain only the 'check_' fields specified in the configuration
          for the monitored registry entries.

    input_description: A test case (ambiguous_checks) is contained in an external YAML file
                       (wazuh_ambiguous_simple.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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
