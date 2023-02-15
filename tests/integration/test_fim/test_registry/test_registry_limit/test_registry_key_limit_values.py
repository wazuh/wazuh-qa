'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.


           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if the FIM event
       'maximum number of entries' has the correct value for the monitored entries limit of
       the 'registries' option.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

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
        scheduled: implies a scheduled scan
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
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import WINDOWS, TIER1
from wazuh_testing.modules.fim import (registry_parser, KEY_WOW64_64KEY, WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY,
                                       MONITORED_KEY_2, MONITORED_KEY_3, REG_SZ, KEY_ALL_ACCESS, RegOpenKeyEx,
                                       RegCloseKey)
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (CB_REGISTRY_LIMIT_VALUE, ERR_MSG_REGISTRY_LIMIT_VALUES,
                                                     CB_COUNT_REGISTRY_ENTRIES, ERR_MSG_FIM_REGISTRY_ENTRIES,
                                                     ERR_MSG_WRONG_NUMBER_OF_ENTRIES, ERR_MSG_FIM_REGISTRY_ENTRIES,
                                                     ERR_MSG_WRONG_REGISTRY_LIMIT_VALUE, CB_COUNT_REGISTRY_ENTRIES)
from wazuh_testing.modules.fim.utils import generate_params, create_registry, modify_registry_value


# Marks
pytestmark = [WINDOWS, TIER1]


# Variables
test_regs = [os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY),
             os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY_2),
             os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY_3)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
monitor_timeout = 40


# Configurations
registry_limit_list = ['1', '2', '3']
conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'WINDOWS_REGISTRY_3': test_regs[2]}
params, metadata = generate_params(extra_params=conf_params,
                                   apply_to_all=({'REGISTRIES': registry_limit_elem} for registry_limit_elem
                                                 in registry_limit_list), modes=['scheduled'])

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
    for key in (MONITORED_KEY, MONITORED_KEY_2, MONITORED_KEY_3):
        reg_handle = create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], key, KEY_WOW64_64KEY)
        reg_handle = RegOpenKeyEx(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], key, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)
        RegCloseKey(reg_handle)


# Tests
def test_registry_limit_values(configure_local_internal_options_module, get_configuration, configure_environment,
                               restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the value of the 'registries' tag, which corresponds to
                 the maximum number of entries to monitor from the 'db_entries_limit' option of FIM. For this purpose,
                 the test will monitor three keys, and the limit for registries to monitor, will change. Then it will
                 check that the FIM event 'maximum number of entries' generated has the correct value of registries.
                 Finally, the test will verify that, in the FIM 'entries' event, the number of entries and monitored
                 values match.

    wazuh_min_version: 4.4.0

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
        - Verify that the FIM event 'maximum number of entries' has the correct value
          for the monitored entries limit of the 'registries' option.

    input_description: A test case (fim_registry_limit) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the limits and the testing registry key to be monitored defined in this module.

    expected_output:
        - r".Maximum number of registry values to be monitored: '(\\d+)'"
        - r".*Fim registry entries count: '(\\d+)'"

    tags:
        - scheduled
    '''
    registry_limit = get_configuration['metadata']['registries']

    for key in (MONITORED_KEY, MONITORED_KEY_2, MONITORED_KEY_3):
        reg_handle = RegOpenKeyEx(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], key, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)
        # Add values to registry plus 1 values over the registry limit
        for i in range(0, int(registry_limit) + 1):
            modify_registry_value(reg_handle, f'value_{i}', REG_SZ, 'added')

    # Look for the file limit value has been configured
    registry_limit_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                   callback=generate_monitoring_callback(CB_REGISTRY_LIMIT_VALUE),
                                                   error_message=ERR_MSG_REGISTRY_LIMIT_VALUES).result()

    # Compare that the value configured is correct
    assert registry_limit_value == registry_limit, ERR_MSG_WRONG_REGISTRY_LIMIT_VALUE

    # Get the ammount of entries monitored and assert they are the same as the limit and not over
    key_entries = wazuh_log_monitor.start(timeout=monitor_timeout,
                                          callback=generate_monitoring_callback(CB_COUNT_REGISTRY_ENTRIES),
                                          error_message=ERR_MSG_FIM_REGISTRY_ENTRIES).result()

    assert key_entries == registry_limit, ERR_MSG_WRONG_NUMBER_OF_ENTRIES
