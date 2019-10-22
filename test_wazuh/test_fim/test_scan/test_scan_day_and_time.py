# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta
from calendar import monthrange

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_end_scan)
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


# functions

def replace_date(date, days):
    """ Adds a number of days to the given date and calculates if it should change the month as well.

    :param date: Datetime with a date
    :param days: Integer with a number of days
    :return: Datetime with the new date
    """
    today = datetime.now()
    max_days_in_month = monthrange(today.year, today.month)[1]
    if today.day + days > max_days_in_month:
        new_day = (today.day + days) % max_days_in_month
        new_month = today.month + 1
    else:
        new_day = today.day + days
        new_month = today.month

    return datetime.replace(date, day=new_day, month=new_month)


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
                           restart_syscheckd, wait_for_initial_scan):
    """ Check if there is a scan in a certain day and time
    TODO Check this test once this configuration is fixed"""
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

    if day_diff < 0:
        day_diff %= 7
    elif day_diff == 0:
        scan_today = True

    scan_time = replace_date(scan_time, day_diff)

    if scan_today:
        if (scan_time - current_day).days == 0:
            TimeMachine.travel_to_future(scan_time - current_day + timedelta(minutes=1))
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
            return
        else:
            day_diff = 7

    if day_diff > 1:
        TimeMachine.travel_to_future(timedelta(days=day_diff - 1))
        current_day = datetime.now()
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)

    TimeMachine.travel_to_future(scan_time - current_day - timedelta(minutes=5))
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
    TimeMachine.travel_to_future(timedelta(minutes=6))
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
