'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       only for registry entry operations in monitored keys that do not match the 'restrict_key'
       or the 'restrict_value' attributes.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_restrict

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
    - fim_registry_restrict
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, create_registry, modify_registry_value, registry_parser, KEY_WOW64_32KEY, \
    KEY_WOW64_64KEY, callback_restricted, generate_params, callback_detect_event, delete_registry_value, \
    check_time_travel, delete_registry, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs

valid_subkey = "key_restrict"
valid_value_name = "value_restrict"
no_valid_subkey = "some_key"
no_valid_value_name = "some_value"

# Configurations
conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'RESTRICT_VALUE': 'value_restrict$',
               'RESTRICT_KEY': 'key_restrict$'}

configurations_path = os.path.join(test_data_path, 'wazuh_restrict_conf.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, subkey, arch, value_name, triggers_event, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, valid_value_name, True, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_32KEY, valid_value_name, True, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_64KEY, valid_value_name, True, {'value_restrict'}),
    (key, sub_key_1, KEY_WOW64_64KEY, no_valid_value_name, False, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_32KEY, no_valid_value_name, False, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_64KEY, no_valid_value_name, False, {'value_restrict'})
])
def test_restrict_value(key, subkey, arch, value_name, triggers_event, tags_to_apply,
                        get_configuration, configure_environment, restart_syscheckd,
                        wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or ignores events in monitored registry entries
                 depending on the value set in the 'restrict_value' attribute. This attribute limit checks to
                 values that match the entered string or regex and its name. For this purpose, the test will
                 monitor a key, create testing values inside it, and make operations on that values. Finally,
                 the test will verify that FIM 'added' and 'modified' events are generated only for the testing
                 values that are not restricted.

    wazuh_min_version: 4.2.0

    tier: 1

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
            brief: Name of the testing value that will be created.
        - triggers_event:
            type: bool
            brief: True if an event must be generated, False otherwise.
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
        - Verify that FIM events are only generated for operations in monitored values
          that do not match the 'restrict_value' attribute.
        - Verify that FIM 'ignoring' events are generated for monitored values that are restricted.

    input_description: A test case (value_restrict) is contained in external YAML file
                       (wazuh_restrict_conf.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing
                       registry keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' events)
        - r'.*Ignoring entry .* due to restriction .*'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    # This shouldn't create an alert because the key is already created
    key_h = create_registry(registry_parser[key], subkey, arch)
    # Create values
    modify_registry_value(key_h, value_name, REG_SZ, "added")
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)

    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event, accum_results=2 if triggers_event else 1).result()

    if triggers_event:
        assert event[0]['data']['type'] == 'modified', 'Key event not modified'
        assert event[0]['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event[0]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        assert event[1]['data']['type'] == 'added', 'Event type not equal'
        assert event[1]['data']['path'] == os.path.join(key, subkey), 'Event path not equal'
        assert event[1]['data']['value_name'] == value_name, 'Value name not equal'
        assert event[1]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Value event arch not equal'
    else:
        assert event['data']['type'] == 'modified', 'Key event not modified'
        assert event['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        while True:
            ignored_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                    callback=callback_restricted,
                                                    error_message='Did not receive expected '
                                                                  '"Sending FIM event: ..." event').result()
            if ignored_value == value_name:
                break

    delete_registry_value(key_h, value_name)
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event, accum_results=2 if triggers_event else 1).result()

    if triggers_event:
        assert event[0]['data']['type'] == 'modified', 'Key event not modified'
        assert event[0]['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event[0]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        assert event[1]['data']['type'] == 'deleted', 'Event type not equal'
        assert event[1]['data']['path'] == os.path.join(key, subkey), 'Event path not equal'
        assert event[1]['data']['value_name'] == value_name, 'Value name not equal'
        assert event[1]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Value event arch not equal'
    else:
        # After deleting the value, we don't expect any message of the value because it's not in the DB
        assert event['data']['type'] == 'modified', 'Key event not modified'
        assert event['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'


@pytest.mark.parametrize('key, subkey, test_subkey, arch, triggers_event, tags_to_apply', [
    (key, sub_key_1, valid_subkey, KEY_WOW64_64KEY, True, {'key_restrict'}),
    (key, sub_key_2, valid_subkey, KEY_WOW64_64KEY, True, {'key_restrict'}),
    (key, sub_key_2, valid_subkey, KEY_WOW64_32KEY, True, {'key_restrict'}),
    (key, sub_key_1, no_valid_subkey, KEY_WOW64_64KEY, False, {'key_restrict'}),
    (key, sub_key_2, no_valid_subkey, KEY_WOW64_64KEY, False, {'key_restrict'}),
    (key, sub_key_2, no_valid_subkey, KEY_WOW64_32KEY, False, {'key_restrict'})
])
def test_restrict_key(key, subkey, test_subkey, arch, triggers_event, tags_to_apply,
                      get_configuration, configure_environment, restart_syscheckd,
                      wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or ignores events in monitored registry entries
                 depending on the value set in the 'restrict_key' attribute. This attribute limit checks to
                 keys that match the entered string or regex and its name. For this purpose, the test will
                 monitor a key, create testing subkeys inside it, and make operations on those subkeys. Finally,
                 the test will verify that FIM 'added' and 'deleted' events are generated only for the testing
                 subkeys that are not restricted.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: The registry key being monitored by syscheck.
        - test_subkey:
            type: str
            brief: Name of the key that will be used for the test
        - arch:
            type: str
            brief: Architecture of the registry.
        - triggers_event:
            type: bool
            brief: True if an event must be generated, False otherwise.
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
        - Verify that FIM events are only generated for operations in monitored keys
          that do not match the 'restrict_key' attribute.
        - Verify that FIM 'ignoring' events are generated for monitored keys that are restricted.

    input_description: A test case (key_restrict) is contained in external YAML file
                       (wazuh_restrict_conf.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing
                       registry keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'deleted' events)
        - r'.*Ignoring entry .* due to restriction .*'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    test_key = os.path.join(subkey, test_subkey)
    create_registry(registry_parser[key], test_key, arch)

    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event, accum_results=1).result()
        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(key, test_key), 'Event path not equal'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Arch not equal'

    else:
        while True:
            ignored_key = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_restricted,
                                                  error_message='Did not receive expected '
                                                                '"Sending FIM event: ..." event').result()
            if ignored_key == os.path.join(key, subkey):
                break

    delete_registry(registry_parser[key], test_key, arch)
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event, accum_results=1).result()

        assert event['data']['type'] == 'deleted', 'key event not equal'
        assert event['data']['path'] == os.path.join(key, test_key), 'Key event wrong path'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key arch not equal'
