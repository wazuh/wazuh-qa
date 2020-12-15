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
from wazuh_testing.tools.time import TimeMachine, reformat_time

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_times = ['9PM', '20:00', '3:07PM']

# configurations

p, m = generate_params(extra_params={'TEST_DIRECTORIES': directory_str, 'SCAN_TIME': scan_times},
                       modes=['scheduled'] * len(scan_times))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


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
                   get_configuration, configure_environment,
                   restart_syscheckd, wait_for_fim_start):
    """
    Check if there is a scan at a certain time

    scan_time option makes sure there is only one scan every 24 hours, at a certain time.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Reformat given time to a readable format since it can be writen in several ways in ossec.conf
    scan_time = reformat_time(get_configuration['metadata']['scan_time'])
    current_time = datetime.now()

    # Calculate how much time we need to travel in time to make sure there hasn't been any scan until it is the given
    # time
    time_difference = (scan_time - current_time) if (scan_time - current_time).days == 0 else \
        ((scan_time - current_time) + timedelta(days=2))
    check_time_travel(time_travel=True, interval=time_difference + timedelta(minutes=-30))
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan)
        raise AttributeError(f'Unexpected event {event}')

    check_time_travel(time_travel=True, interval=timedelta(minutes=31))
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                            error_message='Did not receive expected '
                                          '"File integrity monitoring scan ended" event')
