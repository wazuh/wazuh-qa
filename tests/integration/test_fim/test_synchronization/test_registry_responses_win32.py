'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM synchronizes the
       registry DB when a modification is performed while the agent is down and decodes
       the synchronization events properly.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: synchronization

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os
import sys
import pytest
from wazuh_testing import LOG_FILE_PATH, DATA, WAZUH_SERVICES_START
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.modules.fim.utils import (find_value_in_event_list, get_sync_msgs, generate_params, create_registry,
                                             modify_registry_value)
from wazuh_testing.modules.fim import (FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS, SCHEDULED_MODE, WINDOWS_REGISTRY,
                                       SYNC_INTERVAL, SYNC_INTERVAL_VALUE, YAML_CONF_REGISTRY_RESPONSE, REG_SZ,
                                       WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, registry_parser, KEY_WOW64_64KEY)
from wazuh_testing.modules.fim.event_monitor import detect_initial_scan

# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]


# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), DATA)
configurations_path = os.path.join(test_data_path, YAML_CONF_REGISTRY_RESPONSE)
conf_params = {WINDOWS_REGISTRY: os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY),
               SYNC_INTERVAL: 10}


# configurations
conf_params, conf_metadata = generate_params(extra_params=conf_params, modes=[SCHEDULED_MODE])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)
local_internal_options = FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.skipif(sys.platform == 'win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key_name', [':subkey1', 'subkey2:', ':subkey3:'])
@pytest.mark.parametrize('value_name', [':value1', 'value2:', ':value3:'])
def test_registry_sync_after_restart(key_name, value_name, configure_local_internal_options_module,
                                     get_configuration, configure_environment, create_key):
    '''
    description: Check if the 'wazuh-syscheckd' daemon synchronizes the registry DB when a modification
                 is performed while the agent is down. For this purpose, the test will monitor a key and
                 wait for the synchronization. Then it will stop the agent, make key/value operations inside
                 the monitored key, and start the agent again. Finally, it will wait for the synchronization
                 and verify that FIM sync events generated include the key and value paths for
                 the modifications made.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - key_name:
            type: str
            brief: Name of the subkey that will be created in the test.
        - value_name:
            type: str
            brief: Name of the value that will be created in the test.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_key:
            type: fixture
            brief: Create the test key.

    assertions:
        - Verify that FIM sync events generated include the monitored value path and
          its parent key path of the changes made while the agent was stopped.

    input_description: A test case (registry_sync_responses) is contained in external YAML file
                       (wazuh_conf_registry_responses_win32.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon. That is combined with the
                       testing registry key to be monitored defined in this module.

    expected_output:
        - r'.*#!-fim_registry dbsync no_data (.+)'
        - r'.*Sending integrity control message'

    tags:
        - scheduled
    '''
    key_path = os.path.join(MONITORED_KEY, key_name)
    value_path = os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, key_path, value_name)

    # stops syscheckd
    key_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], key_path, KEY_WOW64_64KEY)

    modify_registry_value(key_handle, value_name, REG_SZ, 'This is a test with syscheckd down.')
    control_service(WAZUH_SERVICES_START)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    detect_initial_scan(wazuh_log_monitor)
    events = get_sync_msgs(timeout=SYNC_INTERVAL_VALUE)

    assert find_value_in_event_list(os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, key_path), value_name,
                                    events) is not None, f"No sync event was found for {value_path}"
