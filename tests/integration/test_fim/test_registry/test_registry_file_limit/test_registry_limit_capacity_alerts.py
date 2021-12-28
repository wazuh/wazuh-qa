'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if the threshold
       set in the 'file_limit' tag generates FIM events when the number of monitored entries
       approaches this value.
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
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_file_limit
'''
import os
from sys import platform
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, modify_registry_value, callback_file_limit_capacity, \
    callback_registry_count_entries, check_time_travel, delete_registry_value, callback_file_limit_back_to_normal, \
    registry_parser, KEY_WOW64_64KEY, callback_detect_end_scan, REG_SZ, KEY_ALL_ACCESS, RegOpenKeyEx, RegCloseKey
from wazuh_testing.fim_module.fim_variables import WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, CB_FILE_LIMIT_CAPACITY, \
    ERR_MSG_DATABASE_PERCENTAGE_FULL_ALERT, ERR_MSG_WRONG_CAPACITY_DB_LIMIT, ERR_MSG_FIM_INODE_ENTRIES, CB_FILE_LIMIT_BACK_TO_NORMAL, \
    ERR_MSG_DB_BACK_TO_NORMAL,CB_COUNT_REGISTRY_FIM_ENTRIES, ERR_MSG_WRONG_NUMBER_OF_ENTRIES
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator
if platform == 'win32':
    import pywintypes

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

KEY = WINDOWS_HKEY_LOCAL_MACHINE
sub_key_1 = MONITORED_KEY

test_regs = [os.path.join(KEY, sub_key_1)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1 = test_regs[0]

# Configurations


file_limit_list = ['100']

conf_params = {'WINDOWS_REGISTRY': reg1, 'MODULE_NAME': __name__}
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


# Tests


@pytest.mark.parametrize('percentage, tags_to_apply', [
    (80, {'file_limit_registry_conf'}),
    (90, {'file_limit_registry_conf'}),
    (0, {'file_limit_registry_conf'})
])
def test_file_limit_capacity_alert(percentage, tags_to_apply, get_configuration, configure_environment,
                                   restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates events for different capacity thresholds limits when
                 using the 'schedule' monitoring mode. For this purpose, the test will monitor a key in which
                 several testing values will be created, corresponding to different percentages of the total limit.
                 Then, it will check if FIM events are generated when the number of values created exceeds 80% of
                 the total and when the number is less than that percentage. Finally, the test will verify that, in
                 the FIM 'entries' event, the entries number is one unit more than the number of monitored values.

    wazuh_min_version: 4.2.0

    parameters:
        - percentage:
            type: int
            brief: Percentage of testing values to be created.
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
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM 'DB alert' events are generated when the number of values to be monitored
          exceeds the established threshold and vice versa.
        - Verify that FIM 'entries' events contain one unit more than the number of monitored values.

    input_description: A test case (file_limit_registry_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the percentages and the testing registry key to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Sending DB .* full alert.'
        - r'.*Sending DB back to normal alert.'
        - r'.*Fim registry entries'

    tags:
        - scheduled
        - time_travel
    '''
    # This import must be here in order to avoid problems in Linux.
    #import pywintypes

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    limit = int(get_configuration['metadata']['file_limit'])

    NUM_REGS = int(limit * (percentage / 100)) + 1

    if percentage == 0:
        NUM_REGS = 0

    reg1_handle = RegOpenKeyEx(registry_parser[KEY], sub_key_1, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    if percentage >= 80:  # Percentages 80 and 90
        for i in range(NUM_REGS):
            modify_registry_value(reg1_handle, f'value_{i}', REG_SZ, 'added')
    else:  # Database back to normal
        for i in range(limit - 10):
            modify_registry_value(reg1_handle, f'value_{i}', REG_SZ, 'added')

        check_time_travel(scheduled, monitor=wazuh_log_monitor)

        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_end_scan,
                                error_message=ERR_MSG_FIM_INODE_ENTRIES)

        for i in range(limit):
            try:
                delete_registry_value(reg1_handle, f'value_{i}')
            except OSError:
                break  # Break out of the loop when all values have been deleted
            except pywintypes.error:
                break

    RegCloseKey(reg1_handle)

    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if percentage >= 80:  # Percentages 80 and 90
        file_limit_capacity = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                      callback=callback_generator(CB_FILE_LIMIT_CAPACITY),
                                                      error_message=ERR_MSG_DATABASE_PERCENTAGE_FULL_ALERT).result()
                                                      
        assert file_limit_capacity == str(percentage), ERR_MSG_WRONG_CAPACITY_DB_LIMIT

    else:  # Database back to normal
        event_found = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                              callback=callback_generator(CB_FILE_LIMIT_BACK_TO_NORMAL),
                                              error_message=ERR_MSG_DB_BACK_TO_NORMAL).result()

    entries = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                      callback=callback_generator(CB_COUNT_REGISTRY_FIM_ENTRIES),
                                      error_message=ERR_MSG_FIM_INODE_ENTRIES).result()

    # We add 1 because of the key created to hold the values
    assert entries == str(NUM_REGS + 1), ERR_MSG_WRONG_NUMBER_OF_ENTRIES
