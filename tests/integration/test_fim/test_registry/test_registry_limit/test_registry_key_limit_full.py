'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM events are
       generated while the database is in 'full database alert' mode for reaching the limit
       of entries to monitor set in the 'registry_limit'-'registries' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
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

from wazuh_testing import global_parameters
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import WINDOWS, TIER1
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim import (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, MONITORED_KEY_2, registry_parser,
                                       KEY_WOW64_64KEY, KEY_ALL_ACCESS, RegOpenKeyEx, RegCloseKey)
from wazuh_testing.modules.fim.event_monitor import (CB_REGISTRY_LIMIT_CAPACITY, ERR_MSG_DATABASE_FULL_ALERT,
                                                     ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT, CB_COUNT_REGISTRY_ENTRIES,
                                                     CB_DATABASE_FULL_COULD_NOT_INSERT_KEY,
                                                     ERR_MSG_FIM_REGISTRY_ENTRIES, ERR_MSG_WRONG_NUMBER_OF_ENTRIES,
                                                     ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL)
from wazuh_testing.modules.fim.utils import generate_params, create_registry

# Marks
pytestmark = [WINDOWS, TIER1]


# Variables
test_regs = [os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY),
             os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY_2)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
NUM_REGS = 2
EXPECTED_DB_STATE = "100"
monitor_timeout = 40


# Configurations
registry_limit_list = ['2']
conf_params = {'WINDOWS_REGISTRY_1': test_regs[0], 'WINDOWS_REGISTRY_2': test_regs[1]}
params, metadata = generate_params(extra_params=conf_params,
                                   apply_to_all=({'REGISTRIES': registry_limit_elem} for registry_limit_elem in
                                                 registry_limit_list), modes=['scheduled'])
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions
def extra_configuration_before_yield():
    """Generate registry entries to fill database"""
    for key in (MONITORED_KEY, MONITORED_KEY_2):
        reg_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], key, KEY_WOW64_64KEY)
        reg_handle = RegOpenKeyEx(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], key, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)
        RegCloseKey(reg_handle)


# Tests
def test_registry_key_limit_full(configure_local_internal_options_module, get_configuration, configure_environment,
                                 restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates proper events while the FIM database is in
                 'full database alert' mode for reaching the limit of entries to monitor set in the 'registries' option
                 of the 'registry_limit' tag.
                 For this purpose, the test will set the a limit of keys to monitor, and will monitor a series of keys.
                 Then, it will try to add a new key and it will check if the FIM event 'full' is generated. Finally, the
                 test will verify that, in the FIM 'entries' event, the number of entries and monitored values match.

    wazuh_min_version: 4.6.0

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
        - r'.*Registry database is (\\d+)% full.'
        - r'.*Couldn't insert ('.*') entry into DB. The DB is full.*'
        - r'.*Fim registry entries count:.*'

    tags:
        - scheduled
    '''
    database_state = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                             callback=generate_monitoring_callback(CB_REGISTRY_LIMIT_CAPACITY),
                                             error_message=ERR_MSG_DATABASE_FULL_ALERT).result()

    assert database_state == EXPECTED_DB_STATE, ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL

    reg_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY+'\\DB_FULL',
                                 KEY_WOW64_64KEY)
    reg_handle = RegOpenKeyEx(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY+'\\DB_FULL', 0,
                              KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    RegCloseKey(reg_handle)

    wazuh_log_monitor.start(timeout=monitor_timeout, error_message=ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT,
                            callback=generate_monitoring_callback(CB_DATABASE_FULL_COULD_NOT_INSERT_KEY))

    key_entries = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=generate_monitoring_callback(CB_COUNT_REGISTRY_ENTRIES),
                                          error_message=ERR_MSG_FIM_REGISTRY_ENTRIES).result()

    assert key_entries == str(get_configuration['metadata']['registries']), ERR_MSG_WRONG_NUMBER_OF_ENTRIES
