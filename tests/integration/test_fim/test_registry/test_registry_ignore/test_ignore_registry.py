'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will verify that FIM ignores the registry entries
       set in the 'registry_ignore' option using both regex and regular names for specifying them.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_ignore

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#registry-ignore

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_ignore
'''
import os
import sys

import pytest
from wazuh_testing import T_20, fim
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
subkey_1 = "SOFTWARE\\test_key"
subkey_2 = "SOFTWARE\\Classes\\test_key"
ignore_key = "key_ignore"
ignore_regex = "ignored_key$"
ignore_value = "value_ignored"
ignore_value_regex = "ignored_value$"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_regs = [os.path.join(key, subkey_1), os.path.join(key, subkey_2)]

reg1, reg2 = test_regs

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'REGISTRY_IGNORE_1': os.path.join(reg1, ignore_key),
               'REGISTRY_IGNORE_2': os.path.join(reg2, ignore_key),
               'REGISTRY_IGNORE_REGEX': ignore_regex,
               'VALUE_IGNORE_1': os.path.join(reg1, ignore_value),
               'VALUE_IGNORE_2': os.path.join(reg2, ignore_value),
               'VALUE_IGNORE_REGEX': ignore_value_regex
               }
configurations_path = os.path.join(test_data_path, 'wazuh_registry_ignore_conf.yaml')
p, m = fim.generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


@pytest.fixture(scope='function')
def reset_registry_ignore_path():
    yield
    fim.registry_ignore_path = None


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('root_key, registry, arch, subkey, triggers_event, tags_to_apply', [
    (key, subkey_1, fim.KEY_WOW64_32KEY, "some_key", True, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "some_key", True, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, ignore_key, False, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, ignore_key, False, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "regex_ignored_key", False, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, "regex_ignored_key", False, {'ignore_registry_key'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "some_key", True, {'ignore_registry_key'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, ignore_key, False, {'ignore_registry_key'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "regex_ignored_key", False, {'ignore_registry_key'})
])
def test_ignore_registry_key(root_key, registry, arch, subkey, triggers_event, tags_to_apply,
                             get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start,
                             reset_registry_ignore_path):
    '''
    description: Check if the 'wazuh-syscheckd' daemon ignores the events from keys that are in a monitored subkey
                 when using the 'registry_ignore' option. It also ensures that events for keys that are not being
                 ignored are still detected. For this purpose, the test will monitor a subkey containing keys to be
                 ignored using names or regular expressions. Then it will create these keys and check if FIM events
                 should be generated. Finally, the test will verify that the FIM events generated are consistent
                 with the ignored keys and monitored subkey.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - root_key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - registry:
            type: str
            brief: Path of the registry entry where the test will be executed.
        - arch:
            type: str
            brief: Architecture of the registry.
        - subkey:
            type: str
            brief: Path of the key that will be created under the root key.
        - triggers_event:
            type: bool
            brief: True if an event must be generated, False otherwise.
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
        - reset_registry_ignore_path:
            type: fixture
            brief: Set to None the 'registry_ignore_path' variable of the 'fim.py' module.

    assertions:
        - Verify that FIM 'ignore' events are generated when an ignored key is modified.
        - Verify that FIM 'added' events are generated when a not ignored key is added.
        - Verify that 'modified' FIM events are generated from a parent key when
          a key is added. Whether it is ignored or not.

    input_description: A test case (ignore_registry_key) is contained in an external YAML file
                       (wazuh_registry_ignore_conf.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing
                       registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)
        - r'.*Ignoring .*? (.*?) due to( sregex)? .*?'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    fim.registry_ignore_path = os.path.join(root_key, registry)

    # Create registry
    fim.create_registry(fim.registry_parser[root_key], os.path.join(registry, subkey), arch)

    # Let syscheck perform a new scan
    if triggers_event:
        event = wazuh_log_monitor.start(timeout=T_20,
                                        callback=fim.callback_key_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        assert event['data']['type'] == 'added', 'Wrong event type.'
        assert event['data']['path'] == os.path.join(root_key, registry, subkey), 'Wrong key path.'
        assert event['data']['arch'] == '[x32]' if arch == fim.KEY_WOW64_32KEY else '[x64]', 'Wrong key arch.'

    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=T_20,
                                            callback=fim.callback_key_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()


@pytest.mark.parametrize('root_key, registry, arch, value, triggers_event, tags_to_apply', [
    (key, subkey_1, fim.KEY_WOW64_32KEY, "some_value", True, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "some_value", True, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "regex_ignored_value", False, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, "regex_ignored_value", False, {'ignore_registry_value'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "regex_ignored_value", False, {'ignore_registry_value'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "some_value", True, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, ignore_value, False, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, ignore_value, False, {'ignore_registry_value'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, ignore_value, False, {'ignore_registry_value'})
])
def test_ignore_registry_value(root_key, registry, arch, value, triggers_event, tags_to_apply,
                               get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon ignores the events from values that are in a monitored subkey
                 when using the 'registry_ignore' option. It also ensures that events for values that are not being
                 ignored are still detected. For this purpose, the test will monitor a subkey containing values to be
                 ignored using names or regular expressions. Then it will create these values and check if FIM events
                 should be generated. Finally, the test will verify that the FIM events generated are consistent
                 with the ignored values and monitored subkey.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - root_key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - registry:
            type: str
            brief: Path of the registry entry where the test will be executed.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value:
            type: str
            brief: Name of the value that will be created.
        - triggers_event:
            type: bool
            brief: True if an event must be generated, False otherwise.
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
        - Verify that FIM 'ignore' events are generated when an ignored value is modified.
        - Verify that FIM 'added' events are generated when a not ignored value is added.
        - Verify that 'modified' FIM events are generated from a parent key when
          a value is added. Whether it is ignored or not.

    input_description: A test case (ignore_registry_value) is contained in an external YAML file
                       (wazuh_registry_ignore_conf.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing
                       registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)
        - r'.*Ignoring .*? (.*?) due to( sregex)? .*?'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Open the key (this shouldn't create an alert)
    key_h = fim.create_registry(fim.registry_parser[root_key], registry, arch)
    # Create values
    fim.modify_registry_value(key_h, value, fim.REG_SZ, "test_value")

    # Let syscheck perform a new scan
    if triggers_event:
        event = wazuh_log_monitor.start(timeout=T_20, callback=fim.callback_value_event,
                                        error_message='Did not receive expected "Sending FIM event:.." event').result()

        assert event['data']['type'] == 'added', 'Wrong event type.'
        assert event['data']['path'] == os.path.join(root_key, registry), 'Wrong value path.'
        assert event['data']['arch'] == '[x32]' if arch == fim.KEY_WOW64_32KEY else '[x64]', 'wrong key arch.'
        assert event['data']['value_name'] == value, 'Wrong value name'

    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=T_20, callback=fim.callback_value_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
