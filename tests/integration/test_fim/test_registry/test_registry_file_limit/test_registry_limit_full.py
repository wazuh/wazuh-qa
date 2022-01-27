'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM events are
       generated while the database is in 'full database alert' mode for reaching the limit
       of entries to monitor set in the 'file_limit' tag.
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
        scheduled:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_file_limit
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, modify_registry_value, registry_parser, KEY_WOW64_64KEY, \
     REG_SZ, KEY_ALL_ACCESS, RegOpenKeyEx, RegCloseKey, create_registry
from wazuh_testing.fim_module import (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, CB_FILE_LIMIT_CAPACITY,
    ERR_MSG_DATABASE_FULL_ALERT_EVENT, ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT, CB_DATABASE_FULL_COULD_NOT_INSERT,
    CB_COUNT_REGISTRY_FIM_ENTRIES, ERR_MSG_FIM_INODE_ENTRIES, ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL,
    ERR_MSG_WRONG_NUMBER_OF_ENTRIES)
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables
KEY = WINDOWS_HKEY_LOCAL_MACHINE
sub_key_1 = MONITORED_KEY

test_reg = os.path.join(KEY, sub_key_1)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
NUM_REGS = 10

# Configurations

file_limit_list = ['10']
conf_params = {'WINDOWS_REGISTRY': test_reg, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'FILE_LIMIT': file_limit_elem} for file_limit_elem in file_limit_list),
                       modes=['scheduled'])

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Generate registry entries to fill database"""
    reg1_handle = create_registry(registry_parser[KEY], sub_key_1, KEY_WOW64_64KEY)
    reg1_handle = RegOpenKeyEx(registry_parser[KEY], sub_key_1, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    for i in range(0, NUM_REGS):
        modify_registry_value(reg1_handle, f'value_{i}', REG_SZ, 'added')

    RegCloseKey(reg1_handle)


# Tests
def test_file_limit_full(get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates proper events while the FIM database is in
                 'full database alert' mode for reaching the limit of entries to monitor set in the 'file_limit' tag.
                 For this purpose, the test will monitor a key in which several testing values will be created
                 until the entry monitoring limit is reached. Then, it will check if the FIM event 'full' is generated
                 when a new testing value is added to the monitored key. Finally, the test will verify that,
                 in the FIM 'entries' event, the number of entries and monitored values match.

    wazuh_min_version: 4.2.0

    parameters:
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

    assertions:
        - Verify that the FIM database is in 'full database alert' mode
          when the maximum number of values to monitor has been reached.
        - Verify that proper FIM events are generated while the database
          is in 'full database alert' mode.

    input_description: A test case (file_limit_registry_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the testing registry key to be monitored defined in this module.

    expected_output:
        - r'.*Sending DB .* full alert.'
        - r'.*The DB is full.*'
        - r'.*Fim registry entries'

    tags:
        - scheduled
    '''
    database_state = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                             callback=callback_generator(CB_FILE_LIMIT_CAPACITY),
                                             error_message=ERR_MSG_DATABASE_FULL_ALERT_EVENT).result()

    assert database_state == '100', ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL

    reg1_handle = RegOpenKeyEx(registry_parser[KEY], sub_key_1, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    modify_registry_value(reg1_handle, 'value_full', REG_SZ, 'added')

    RegCloseKey(reg1_handle)

    wazuh_log_monitor.start(timeout=40, callback=callback_generator(CB_DATABASE_FULL_COULD_NOT_INSERT),
                            error_message=ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT)

    entries = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                      callback=callback_generator(CB_COUNT_REGISTRY_FIM_ENTRIES),
                                      error_message=ERR_MSG_FIM_INODE_ENTRIES).result()

    assert entries == str(get_configuration['metadata']['file_limit']), ERR_MSG_WRONG_NUMBER_OF_ENTRIES
