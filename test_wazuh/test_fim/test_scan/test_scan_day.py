# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_end_scan)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, TimeMachine)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_days = ['monday', 'thursday', 'wednesday']

# configurations


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'SCAN_DAY': scan_days[0]},
                                                   {'SCAN_DAY': scan_days[1]},
                                                   {'SCAN_DAY': scan_days[2]}
                                                   ],
                                           metadata=[{'scan_day': scan_days[0]},
                                                     {'scan_day': scan_days[1]},
                                                     {'scan_day': scan_days[2]}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'scan_day'}
])
def test_scan_day(tags_to_apply,
                  get_configuration, configure_environment, wait_for_initial_scan,
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
    current_day = datetime.now().weekday()
    scan_day = day_of_week[get_configuration['metadata']['scan_day']]
    day_diff = scan_day - current_day
    print(f'Current: {current_day}')
    # Check if difference is negative
    if day_diff < 0:
        day_diff %= 7
    elif day_diff == 0:
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
        pass

    if day_diff > 1:
        TimeMachine.travel_to_future(timedelta(days=day_diff - 1))
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
    TimeMachine.travel_to_future(timedelta(days=1))
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_end_scan)
