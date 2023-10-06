'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       of type 'deleted' from the values contained in a registry key that is being deleted.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_basic_usage

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
    - fim_registry_basic_usage
'''
import os
import sys
from collections import Counter

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_registry, modify_registry_value, delete_registry, \
    callback_value_event, check_time_travel, validate_registry_value_event, registry_parser, KEY_WOW64_32KEY, \
    KEY_WOW64_64KEY, REG_SZ, REG_MULTI_SZ, REG_DWORD
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"

test_regs = [os.path.join(key, sub_key_1), os.path.join(key, sub_key_2)]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
reg1, reg2 = test_regs

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1, 'WINDOWS_REGISTRY_2': reg2}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_both.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

registry_list = [(key, sub_key_1, KEY_WOW64_64KEY),
                 (key, sub_key_2, KEY_WOW64_32KEY),
                 (key, sub_key_2, KEY_WOW64_64KEY)]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# test
@pytest.mark.skipif(sys.platform == 'win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, subkey, arch, value_list', [
    (key, sub_key_1, KEY_WOW64_64KEY, ['value1', 'value2', 'value3']),
    (key, sub_key_2, KEY_WOW64_32KEY, ['value1', 'value2', 'value3']),
    (key, sub_key_2, KEY_WOW64_64KEY, ['value1', 'value2', 'value3'])

])
def test_delete_registry(key, subkey, arch, value_list,
                         get_configuration, configure_environment,
                         restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'deleted' events from the values contained
                 in a registry key that is being deleted. For this purpose, the test will monitor a registry
                 key and create several values inside it. Then, it will remove the registry key, and finally,
                 the test will verify that FIM 'deleted' events are generated for the values that were inside
                 the registry key.

    wazuh_min_version: 4.2.0

    tier: 0

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
        - value_list:
            type: list
            brief: List with the name of the values that will be used.
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
        - Verify that FIM 'deleted' events are generated from values found
          in a monitored registry key when removed.

    input_description: A test case (ossec_conf_2) is contained in an external YAML file
                       (wazuh_conf_registry_both.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'

    key_h = create_registry(registry_parser[key], subkey, arch)

    # Create values inside subkey
    modify_registry_value(key_h, value_list[0], REG_SZ, "some content")
    modify_registry_value(key_h, value_list[1], REG_MULTI_SZ, "some content\0second string\0")
    modify_registry_value(key_h, value_list[2], REG_DWORD, 1234)

    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_value_event,
                                     accum_results=len(value_list),
                                     error_message='Did not receive expected "Sending FIM event: ..." event').result()
    for ev in events:
        validate_registry_value_event(ev, mode=mode)

    # Remove registry
    delete_registry(registry_parser[key], subkey, arch)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    # Expect deleted events
    event_list = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_value_event,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event',
                                         accum_results=len(value_list)).result()
    counter_type = Counter([event['data']['type'] for event in event_list])

    for ev in events:
        validate_registry_value_event(ev, mode=mode)

    assert counter_type['deleted'] == len(value_list), f'Number of "deleted" events should be {len(value_list)}'

    name_list = set([event['data']['value_name'] for event in event_list])
    for value in value_list:
        assert value in name_list, f'Value {value} not found within the events'
