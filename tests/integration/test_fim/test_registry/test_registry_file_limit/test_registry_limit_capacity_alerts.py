# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, modify_registry_value, callback_file_limit_capacity, \
    callback_registry_count_entries, check_time_travel, delete_registry_value, callback_file_limit_back_to_normal, \
    registry_parser, KEY_WOW64_64KEY, callback_detect_end_scan, REG_SZ, KEY_ALL_ACCESS, RegOpenKeyEx, RegCloseKey
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks


pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables


KEY = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"

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
    """
    Checks that the corresponding alerts appear in schedule mode for different capacity thresholds.

    Parameters
    ----------
    percentage : int
        Percentage of full database.
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    # This import must be here in order to avoid problems in Linux.
    import pywintypes

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
                                error_message='Did not receive expected '
                                              '"Fim inode entries: ..., path count: ..." event')

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
                                                      callback=callback_file_limit_capacity,
                                                      error_message='Did not receive expected '
                                                                    '"DEBUG: ...: Sending DB ...% full alert." event'
                                                      ).result()

        if file_limit_capacity:
            assert file_limit_capacity == str(percentage), 'Wrong capacity log for DB file_limit'
        else:
            pytest.fail('Wrong capacity log for DB file_limit')
    else:  # Database back to normal
        event_found = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                              callback=callback_file_limit_back_to_normal,
                                              error_message='Did not receive expected '
                                                            '"DEBUG: ...: Sending DB back to normal alert." event'
                                              ).result()

        assert event_found, 'Event "Sending DB back to normal alert." not found'

    entries = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                      callback=callback_registry_count_entries,
                                      error_message='Did not receive expected '
                                                    '"Fim inode entries: ..., path count: ..." event'
                                      ).result()

    if entries:
        # We add 1 because of the key created to hold the values
        assert entries == str(NUM_REGS + 1), 'Wrong number of entries count.'
    else:
        pytest.fail('Wrong number of entries count')
