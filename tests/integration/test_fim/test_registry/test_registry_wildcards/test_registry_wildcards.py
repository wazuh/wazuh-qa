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
import pytest
from wazuh_testing import LOG_FILE_PATH, global_parameters
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import WINDOWS, TIER1
from wazuh_testing.modules.fim import (registry_parser, KEY_WOW64_64KEY, REG_SZ, KEY_ALL_ACCESS, RegOpenKeyEx,
                                       RegCloseKey, WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY)
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import functions
from wazuh_testing.modules.fim.utils import modify_registry_value

# Marks
pytestmark = [WINDOWS, TIER1]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_registry_wildcards.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_registry_wildcards.yaml')


# Enabled test configurations (t1)
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                             configuration_metadata)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
monitor_timeout = 40




# Tests
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_registry_value_wildcards(configure_local_internal_options_module, get_configuration, configure_environment,
                                   restart_syscheckd):
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
        - r".*Registry database is (\\d+)% full."
        - r".*Couldn't insert ('.*') entry into DB. The DB is full.*"
        - r".*Fim registry values entries count: '(\\d+)'"

    tags:
        - scheduled
    '''
    reg1_handle = RegOpenKeyEx(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY, 0,
                               KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    # Check Key/Value is being monitored
    # Modify Key/Value
    modify_registry_value(reg1_handle, 'value_full', REG_SZ, 'added')
    RegCloseKey(reg1_handle)
    # Check modification is detected
    # Delete Key/Value  
