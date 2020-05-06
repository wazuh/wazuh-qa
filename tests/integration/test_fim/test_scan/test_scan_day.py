# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_end_scan, generate_params, check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_days = ['monday', 'thursday', 'wednesday']

# configurations

p, m = generate_params(extra_params={'TEST_DIRECTORIES': directory_str, 'SCAN_DAY': scan_days},
                       modes=['scheduled'] * len(scan_days))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


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
                  get_configuration, configure_environment,
                  restart_syscheckd, wait_for_initial_scan):
    """Check if there is a scan at a certain day of the week

    It will only scan once a week, on the given day.
    """
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

    if day_diff < 0:
        day_diff %= 7
    elif day_diff == 0:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_end_scan)
            raise AttributeError(f'Unexpected event {event}')
        return

    if day_diff > 1:
        check_time_travel(time_travel=True, interval=timedelta(days=day_diff - 1))
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_end_scan)
            raise AttributeError(f'Unexpected event {event}')
    check_time_travel(time_travel=True, interval=timedelta(days=1))
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                            error_message='Did not receive expected '
                                          '"File integrity monitoring scan ended" event')
