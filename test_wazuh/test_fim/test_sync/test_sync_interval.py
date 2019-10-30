# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta
import pytest
import time
from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_synchronization, detect_initial_scan, callback_configuration_warning)
from wazuh_testing.tools import (FileMonitor, truncate_file, check_apply_test, load_wazuh_configurations, reformat_time, TimeMachine, time_to_timedelta)


# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
sync_intervals = ['10', '10s', '10m', '10h', '10d', '10w']


# configurations

params=[]
metadata=[]
for interval in sync_intervals:
    params.append({'SYNC_INTERVAL': interval})
    metadata.append({'sync_interval': interval})
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_sync_interval(get_configuration, configure_environment, restart_syscheckd):
    """Verify that synchronization checks take place at the expected time given SYNC_INTERVAL variable.
    
    This test is intended to be used with valid ignore configurations.
    """
    def truncate_log():
        truncate_file(LOG_FILE_PATH)
        return FileMonitor(LOG_FILE_PATH)
    
    # Check if the test should be skipped
    check_apply_test({'sync_interval'}, get_configuration['tags'])
    
    wazuh_log_monitor = truncate_log()
    detect_initial_scan(wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_synchronization)

    wazuh_log_monitor = truncate_log()
    TimeMachine.travel_to_future(time_to_timedelta(get_configuration['metadata']['sync_interval']))
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_synchronization)

    # This should fail as we are only advancing half the time needed for synchronization to occur
    wazuh_log_monitor = truncate_log()
    TimeMachine.travel_to_future(time_to_timedelta(get_configuration['metadata']['sync_interval'])/2)
    try:
        result = wazuh_log_monitor.start(timeout=1,
                                        callback=callback_detect_synchronization,
                                        accum_results=1
                                        ).result()
        if result is not None:
            pytest.fail("Synchronization shouldn't happen at this point")
    except TimeoutError:
        return
