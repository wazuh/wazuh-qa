# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_end_scan)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, reformat_time, TimeMachine)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_times = ['9PM', '20:00', '3:07PM']
# configurations


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'SCAN_TIME': scan_times[0]},
                                                   {'SCAN_TIME': scan_times[1]},
                                                   {'SCAN_TIME': scan_times[2]}
                                                   ],
                                           metadata=[{'scan_time': scan_times[0]},
                                                     {'scan_time': scan_times[1]},
                                                     {'scan_time': scan_times[2]}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'scan_time'}
])
def test_scan_time(tags_to_apply,
                   get_configuration, configure_environment, wait_for_initial_scan,
                   restart_syscheckd):
    """ Check if there is a scan at a certain time """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    scan_time = reformat_time(get_configuration['metadata']['scan_time'])
    current_time = datetime.now()

    time_difference = (scan_time - current_time) if (scan_time - current_time).days == 0 else \
        ((scan_time - current_time) + timedelta(days=2))
    TimeMachine.travel_to_future(time_difference + timedelta(minutes=-30))
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
    TimeMachine.travel_to_future(timedelta(minutes=31))
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
