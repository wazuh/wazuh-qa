'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files are
       modified. Specifically, these tests will check the use of wildcards '*' or '?' when configuring windows
       registries to be monitored. When using wildcards, they should be expanded and matching keys should be
       configured to be monitored. The tests will verify registry keys and values events are properly generated
       when they are created, modified and deleted in registries configured through wildcards expansion.

components:
    - fim

suite: registry_wildcards

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
    - fim_registry_wildcards
'''
import os
import time
import pytest
from wazuh_testing import LOG_FILE_PATH, T_10
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import WINDOWS, TIER1
from wazuh_testing.modules.fim import (registry_parser, KEY_WOW64_64KEY, REG_SZ,
                                       WINDOWS_HKEY_LOCAL_MACHINE)
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (CB_FIM_WILDCARD_EXPANDING, callback_key_event, get_messages,
                                                     check_registry_crud_event, callback_value_event)
from wazuh_testing.modules.fim.utils import (create_registry, modify_registry_value, delete_registry,
                                             delete_registry_value)

# Marks
pytestmark = [WINDOWS, TIER1]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_templates')
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

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
key_name = 'test_key'
value_name = 'test_value'


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_registry_key_wildcards(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                                configure_local_internal_options_function, restart_wazuh_function,
                                wait_syscheck_start):
    '''
    description: Check the behavior of FIM when using wildcards to configure the path of registry keys, and validate
                 the keys creation, modification and deletion is detected correctly.

    wazuh_min_version: 4.6.0

    test_phases:
        - setup:
            - Set wazuh configuration.
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Check that one or more keys are detected when the configured wildcard is expanded
            - Create a subkey inside the first monitored key and check
            - Wait for scan and check subkey has been detected as 'added'
            - Modify the subkey
            - Wait for scan and check subkey has been detected as 'modified'
            - Delete the subkey
            - Wait for scan and check subkey has been detected as 'deleted'
        - teardown:
            - Restore configuration
            - Stop wazuh

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for to apply in agentt.
        - metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh's configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the logs and alerts files.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options configuration.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the logs.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting fim scan is detected.

    assertions:
        - One or more keys have been configured after wildcard expansion
        - Assert 'registry_key added' event has been detected
        - Assert 'registry_key modified' event has been detected
        - Assert 'registry_key deleted' event has been detected

    input_description:
        - The file 'configuration_registry_wildcards.yaml' contains the configuration template for the test.
        - The file 'cases_registry_key_wildcards.yaml' contains test case descriptions, configuration values and
          metadata for each case.

    expected_output:
        - r".*Expanding entry '.*' to '(.*)' to monitor FIM events."
        - r".*Sending FIM event: (.+)$" - For 'registry_key' attributes.type and 'added/modified/deleted' type.

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
    event_added = check_registry_crud_event(callback=callback_key_event, path=path, type='added', timeout=T_10,
                                            arch='x64')
    assert event_added is not None, 'Did not find the expected "registry_key added" event'

    # Add new value in the key and detect the modification of created monitored key is detected
    modify_registry_value(reg_handle, value_name, REG_SZ, 'new_value')
    event_modified = check_registry_crud_event(callback=callback_key_event, path=path, type='modified', timeout=T_10,
                                               arch='x64')
    assert event_modified is not None, 'Did not find the expected "registry_key modified" event'

    # Delete the created key and check it's deletion is detected
    delete_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], subkey, KEY_WOW64_64KEY)
    event_deleted = check_registry_crud_event(callback=callback_key_event, path=path, type='deleted', timeout=T_10,
                                              arch='x64')
    assert event_deleted is not None, 'Did not find the expected "registry_key deleted" event'


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_registry_value_wildcards(configuration, metadata, set_wazuh_configuration,
                                  configure_local_internal_options_function, restart_syscheck_function,
                                  wait_syscheck_start):
    '''
    description: Check the behavior of FIM when using wildcards to configure the path of registry keys, and validate
                 when values are created inside a monitored key, creation, modification and deletion is detected
                 correctly.

    wazuh_min_version: 4.5.0

    test_phases:
        - setup:
            - Set wazuh configuration.
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Check that one or more keys are detected when the configured wildcard is expanded
            - Create a registry_value inside the first monitored key and check
            - Wait for scan and check registry_value has been detected as 'added'
            - Modify the registry_value
            - Wait for scan and check registry_value has been detected as 'modified'
            - Delete the registry_value
            - Wait for scan and check registry_value has been detected as 'deleted'
        - teardown:
            - Restore configuration
            - Stop wazuh

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values to apply to agent.
        - metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh's configuration file.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options configuration.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the logs.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting fim scan is detected.

    assertions:
        - One or more keys have been configured after wildcard expansion
        - Assert 'registry_value added' event has been detected
        - Assert 'registry_value modified' event has been detected
        - Assert 'registry_value deleted' event has been detected

    input_description:
        - The file 'configuration_registry_wildcards.yaml' contains the configuration template for the test.
        - The file 'cases_registry_value_wildcards.yaml' contains test case descriptions, configuration values and
          metadata for each case.

    expected_output:
        - r".*Expanding entry '.*' to '(.*)' to monitor FIM events."
        - r".*Sending FIM event: (.+)$" - For 'registry_value' attributes.type and 'added/modified/deleted' type.
    tags:
        - scheduled
    '''

    monitored_keys = get_messages(generate_monitoring_callback(CB_FIM_WILDCARD_EXPANDING), timeout=T_10)
    assert monitored_keys != [], f"Did not receive expected '{CB_FIM_WILDCARD_EXPANDING}' events"

    subkey = monitored_keys[0].replace(f"{WINDOWS_HKEY_LOCAL_MACHINE}\\", "")
    subkey = subkey + f"\\{key_name}"
    path = monitored_keys[0] + f"\\{key_name}"

    # Create custom key and custom value
    reg_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], subkey, KEY_WOW64_64KEY)
    modify_registry_value(reg_handle, value_name, REG_SZ, 'added')
    event_added = check_registry_crud_event(callback=callback_value_event, path=path, type='added', timeout=T_10,
                                            arch='x64')
    assert event_added is not None, 'Did not find the expected "registry_value added" event'

    # Add new value in the key and detect the modification of created monitored key is detected
    modify_registry_value(reg_handle, value_name, REG_SZ, 'modified')
    event_modified = check_registry_crud_event(callback=callback_value_event, path=path, type='modified', timeout=T_10,
                                               arch='x64')
    assert event_modified is not None, 'Did not find the expected "registry_value modified" event'

    # Delete the created key and check it's deletion is detected
    delete_registry_value(reg_handle, value_name)
    event_deleted = check_registry_crud_event(callback=callback_value_event, path=path, type='deleted', timeout=T_10,
                                              arch='x64')
    assert event_deleted is not None, 'Did not find the expected "registry_value deleted" event'

    # Delete key to clean enviroment
    delete_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], subkey, KEY_WOW64_64KEY)
