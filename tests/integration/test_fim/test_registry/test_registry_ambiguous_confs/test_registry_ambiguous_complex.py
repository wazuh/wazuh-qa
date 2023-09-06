'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM watches selected
       files and triggering alerts when these files are modified. All these tests will be performed
       using complex paths and ambiguous configurations, such as keys and subkeys with opposite
       monitoring settings.
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
from wazuh_testing.fim import CHECK_OWNER, LOG_FILE_PATH, registry_value_cud, registry_key_cud, \
    generate_params, CHECK_SUM, CHECK_TYPE, CHECK_GROUP, \
    CHECK_ALL, CHECK_MTIME, CHECK_SIZE, \
    REQUIRED_REG_KEY_ATTRIBUTES, REQUIRED_REG_VALUE_ATTRIBUTES
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

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
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key', [key])
@pytest.mark.parametrize('subkey, key_checkers', [
    (registry, checkers_key),
    (subkey_1, checkers_subkey1),
    (subkey_2, checkers_subkey2),
    (subkey_3, checkers_subkey3)
])
def test_ambiguous_complex_checks(key, subkey, key_checkers,
                                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds, in the generated events, the 'check_' fields
                 specified in the configuration. These checks are attributes indicating that a monitored key
                 has been modified. For this purpose, the test will monitor several registry keys, and
                 configure different 'checks' for them. Then, it will make operations using testing keys/values
                 to generate events, and finally, the test will verify that the FIM events generated contain only
                 the 'check_' fields specified for the monitored key/values.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - key_checkers:
            type: set
            brief: Set of 'check_' fields that are expected.
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
        - Verify that FIM events generated contain only the 'check_' fields specified in the configuration.

    input_description: A test case (complex_checks) is contained in an external YAML file
                       (wazuh_complex_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the
                       testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({"complex_checks"}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                     options=key_checkers, time_travel=True)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       options=key_checkers, time_travel=True)


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key', [key])
@pytest.mark.parametrize('subkey, value_list, report,', [
    (registry, ['test_value'], True),
    (subkey_1, ['test_value'], False),
    (subkey_2, ['test_value'], False),
    (subkey_3, ['test_value'], True)
])
def test_ambiguous_report_changes(key, subkey, value_list, report,
                                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates or not the 'content_changes' field for each event
                 depending on the value set in the 'report_changes' attribute. This attribute allows reporting the
                 modifications made in a monitored key. For this purpose, the test will monitor a registry key,
                 and make operations using a testing value. Finally, it will verify that FIM events generated
                 contain the changes made in the 'content_changes' field when required.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - value_list:
            type: list
            brief: List with the name of the values that will be used in the CUD operations.
        - report:
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
          in the monitored value when 'report_changes == yes' and vice versa.

    input_description: A test case (complex_report_changes) is contained in an external YAML file
                       (wazuh_complex_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the
                       testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key', [key])
@pytest.mark.parametrize('subkey, tag', [
    (registry, None),
    (subkey_1, tag_1),
    (subkey_2, tag_2),
    (subkey_3, tag_3)
])
def test_ambiguous_report_tags(key, subkey, tag,
                               get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates or not the 'tags' field for each event
                 depending on the value(s) set in the 'tags' attribute. This attribute allows adding tags
                 to the FIM events for monitored keys. For this purpose, the test will monitor a registry
                 key, and make CUD (create, update, and delete) operations using testing keys/values. Finally,
                 it will verify that FIM events generated include in its 'tag' field the tags required.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - tag:
            type: str
            brief: Tag configured for each entry. If None, the entry is not configured with a tag.
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
        - Verify that the 'tags' field is not generated in FIM events
          when the 'tags' attribute not exists or is empty.
        - Verify that FIM events generated contain the proper content in the 'tags' field
          when the 'tags' attribute has content.

    input_description: A test case (complex_tags) is contained in an external YAML file
                       (wazuh_complex_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the
                       testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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
                     validators_after_update=validator_after_update, validators_after_delete=validator_after_delete)

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                       time_travel=True, validators_after_create=validator_after_create,
                       validators_after_update=validator_after_update, validators_after_delete=validator_after_delete)
