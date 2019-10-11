# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_start_scan)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, TimeMachine, reformat_time)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_days = ['thursday', 'wednesday']
scan_times = ['9PM', '20:00']

# configurations


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'SCAN_DAY': scan_days[0], 'SCAN_TIME': scan_times[0]},
                                                   {'SCAN_DAY': scan_days[1], 'SCAN_TIME': scan_times[1]},
                                                   ],
                                           metadata=[{'scan_day': scan_days[0], 'scan_time': scan_times[0]},
                                                     {'scan_day': scan_days[1], 'scan_time': scan_times[1]},
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'scan_both'}
])
def test_scan_day_and_time(tags_to_apply,
                           get_configuration, configure_environment,
                           restart_syscheckd):
    """ Check if there is a scan at a certain day """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    day_of_week = {'monday': 0,
                   'tuesday': 1,
                   'wednesday': 2,
                   'thursday': 3,
                   'friday': 4,
                   'saturday': 5,
                   'sunday': 6
                   }
    current_day = datetime.now()
    scan_day = day_of_week[get_configuration['metadata']['scan_day']]
    scan_time = reformat_time(get_configuration['metadata']['scan_time'])
    day_diff = scan_day - current_day.weekday()
    scan_today = False
    # Check if difference is negative
    if day_diff < 0:
        day_diff %= 7
    elif day_diff == 0:
        scan_today = True

    scan_time.replace(day=(datetime.now().day + day_diff))
    print(f'*********\n\nToday: {datetime.now()}\nScan_time: {scan_time}\n\n')

    if scan_today:
        if (scan_time - current_day).days == 0:
            TimeMachine.travel_to_future(timedelta(scan_time - current_day))
            wazuh_log_monitor.start(timeout=3, callback=callback_detect_start_scan)
            pass
        else:
            day_diff = 7

    if day_diff > 1:
        TimeMachine.travel_to_future(timedelta(days=day_diff - 1))
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=3, callback=callback_detect_start_scan)

    TimeMachine.travel_to_future(scan_time - current_day)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_start_scan)
    TimeMachine.travel_to_future(timedelta(minutes=6))
    wazuh_log_monitor.start(timeout=3, callback=callback_detect_start_scan)
