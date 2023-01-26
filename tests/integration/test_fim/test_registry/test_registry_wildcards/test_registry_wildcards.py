'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM events are
       generated while the database is in 'full database alert' mode for reaching the limit
       of entries to monitor set in the 'registry_limit'-'entries' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_file_limit

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-limit

pytest_args:
    - fim_mode:
        scheduled: file/registry changes are monitored only at the configured interval
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_limit
'''
import os
import time
import pytest
from wazuh_testing import LOG_FILE_PATH, T_10, T_30
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import WINDOWS, TIER1
from wazuh_testing.modules.fim import (registry_parser, KEY_WOW64_64KEY, REG_SZ,
                                       WINDOWS_HKEY_LOCAL_MACHINE)
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (CB_FIM_WILDCARD_EXPANDING, callback_key_event, get_messages,
                                                     callback_value_event, check_registry_crud_event)
from wazuh_testing.modules.fim.utils import (create_values_content, registry_value_create,
                                             registry_value_update, registry_value_delete, create_registry,
                                             modify_registry_value, delete_registry)

# Marks
pytestmark = [WINDOWS, TIER1]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_registry_wildcards.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_registry_key_wildcards.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_registry_value_wildcards.yaml')

# Enabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)


wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
key_name = 'test_key'
value_name = 'test_value'


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_registry_key_wildcards(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                configure_local_internal_options_function, restart_wazuh_function,
                                wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates proper events while the FIM database is in
                 'full database alert' mode for reaching the limit of entries to monitor set in the 'entries' option
                 of the 'registry_limit' tag.
                 For this purpose, the test will monitor a key in which several testing values will be created
                 until the entry monitoring limit is reached. Then, it will check if the FIM event 'full' is generated
                 when a new testing value is added to the monitored key. Finally, the test will verify that,
                 in the FIM 'entries' event, the number of entries and monitored values match.

    wazuh_min_version: 4.5.0

    tier: 1

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Set the local_internal_options for the test.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the Wazuh logs file and start a new monitor.

    assertions:
        - Verify that the FIM database is in 'full database alert' mode
          when the maximum number of values to monitor has been reached.
        - Verify that proper FIM events are generated while the database
          is in 'full database alert' mode.

    input_description: A test case (fim_registry_limit) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the testing registry key to be monitored defined in this module.

    expected_output:
        -

    tags:
        - scheduled
    '''

    # Check logs for wildcards expansion and actual monitored keys
    monitored_keys = get_messages(generate_monitoring_callback(CB_FIM_WILDCARD_EXPANDING), timeout=T_10)
    assert monitored_keys != [], f"Did not receive expected '{CB_FIM_WILDCARD_EXPANDING}' events"

    subkey = monitored_keys[0].replace(f"{WINDOWS_HKEY_LOCAL_MACHINE}\\", "")
    subkey = subkey + f"\\{key_name}"
    path = monitored_keys[0] + f"\\{key_name}"

    # Create a new key inside monitored key and check it is detected
    reg_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], subkey, KEY_WOW64_64KEY)
    event = check_registry_crud_event(callback=callback_key_event, path=path, type='added', timeout=T_10)
    assert event is not None, 'Did not find the expected "registry_key added" event'

    # Add new value in the key and detect the modification of created monitored key is detected
    modify_registry_value(reg_handle, value_name, REG_SZ, 'added')
    event = check_registry_crud_event(callback=callback_key_event, path=path, type='modified', timeout=T_10)
    assert event is not None, 'Did not find the expected "registry_key modified" event'

    # Delete the created key and check it's deletion is detected
    delete_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], subkey, KEY_WOW64_64KEY)
    event = check_registry_crud_event(callback=callback_key_event, path=path, type='deleted', timeout=T_10)
    assert event is not None, 'Did not find the expected "registry_key deleted" event'


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_registry_value_wildcards(configuration, metadata, set_wazuh_configuration,
                                  configure_local_internal_options_function, restart_syscheck_function,
                                  wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates proper events while the FIM database is in
                 'full database alert' mode for reaching the limit of entries to monitor set in the 'entries' option
                 of the 'registry_limit' tag.
                 For this purpose, the test will monitor a key in which several testing values will be created
                 until the entry monitoring limit is reached. Then, it will check if the FIM event 'full' is generated
                 when a new testing value is added to the monitored key. Finally, the test will verify that,
                 in the FIM 'entries' event, the number of entries and monitored values match.

    wazuh_min_version: 4.5.0

    tier: 1

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Set the local_internal_options for the test.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the Wazuh logs file and start a new monitor.

    assertions:
        - Verify that the FIM database is in 'full database alert' mode
          when the maximum number of values to monitor has been reached.
        - Verify that proper FIM events are generated while the database
          is in 'full database alert' mode.

    input_description: A test case (fim_registry_limit) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the testing registry key to be monitored defined in this module.

    expected_output:
        -

    tags:
        - scheduled
    '''
    values = create_values_content(value_name, 10)
    scan_delay = metadata['interval']

    monitored_keys = get_messages(generate_monitoring_callback(CB_FIM_WILDCARD_EXPANDING))
    assert monitored_keys != [], f"Did not receive expected '{CB_FIM_WILDCARD_EXPANDING}' events"
    subkey = monitored_keys[0].replace(f"{WINDOWS_HKEY_LOCAL_MACHINE}\\", "")
    subkey = subkey+f"\\{key_name}"

    # Create custom key
    reg_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], subkey, KEY_WOW64_64KEY)
    
    # Create the value inside the key
    registry_value_create(key, subkey, wazuh_log_monitor, arch=KEY_WOW64_64KEY, value_list=values, wait_for_scan=True,
                          scan_delay=scan_delay, min_timeout=T_30, triggers_event=True)
    # Modify the value
    registry_value_update(key, subkey, wazuh_log_monitor, arch=KEY_WOW64_64KEY, value_list=values, wait_for_scan=True,
                          scan_delay=scan_delay, min_timeout=T_30, triggers_event=True)
    # Delete the value created to clean up enviroment
    registry_value_delete(key, subkey, wazuh_log_monitor, arch=KEY_WOW64_64KEY, value_list=values, wait_for_scan=True,
                          scan_delay=scan_delay, min_timeout=T_30, triggers_event=True)
