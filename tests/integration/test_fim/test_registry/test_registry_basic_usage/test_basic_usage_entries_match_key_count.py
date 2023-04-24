'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM detects the number
       of modifications made on monitored registry entries.
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

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.fim import registry_parser, KEY_WOW64_64KEY, REG_SZ, REG_MULTI_SZ, REG_DWORD
from wazuh_testing.modules.fim.utils import generate_params, create_registry, modify_registry_value
from wazuh_testing.modules.fim.event_monitor import CB_FIM_REGISTRY_ENTRIES_COUNT, CB_FIM_REGISTRY_VALUES_ENTRIES_COUNT

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

arch = KEY_WOW64_64KEY
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"

test_regs = [os.path.join(key, sub_key_1)]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
reg1 = os.path.join(key, sub_key_1)

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_reg_attr.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def extra_configuration_before_yield():
    key_h = create_registry(registry_parser[key], sub_key_1, arch)

    modify_registry_value(key_h, "value1", REG_SZ, "some content")
    modify_registry_value(key_h, "value2", REG_MULTI_SZ, "some content\0second string\0")
    modify_registry_value(key_h, "value3", REG_DWORD, 1234)


def test_entries_match_key_count(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the correct number of events when adding
                 registry entries. For this purpose, the test will add and monitor a registry key. Then,
                 it will create several values inside it, and finally, the test will verify that an FIM
                 event is generated indicating the number of entries added for the key and values added.

    wazuh_min_version: 4.2.0

    tier: 0

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
        - Verify that the FIM event is generated with the number of changes
          made on the monitored registry entries.

    input_description: A test case (ossec_conf_2) is contained in an external YAML file
                       (wazuh_conf_reg_attr.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       key to be monitored defined in the module.

    expected_output:
        - r'.*Fim registry entries'

    tags:
        - scheduled
        - time_travel
    '''
    registry_entries = wazuh_log_monitor.start(timeout=T_20, update_position=False,
                                               callback=generate_monitoring_callback(CB_FIM_REGISTRY_ENTRIES_COUNT),
                                               error_message=f'Did not receive expected \
                                                              "{CB_FIM_REGISTRY_ENTRIES_COUNT}" event').result()

    callback = generate_monitoring_callback(CB_FIM_REGISTRY_VALUES_ENTRIES_COUNT)
    value_entries = wazuh_log_monitor.start(timeout=T_20, callback=callback,
                                            error_message=f'Did not receive expected \
                                                           "{CB_FIM_REGISTRY_VALUES_ENTRIES_COUNT}" event').result()

    assert int(registry_entries) + int(value_entries) == 4, 'Wrong number of entries'
