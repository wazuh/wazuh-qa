'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if the 'wazuh-syscheckd' daemon runs the scans
       on a specific day of the week and time, set them in the 'scan_day' and 'scan_time' tags.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_scan

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#scan-day
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#scan-time

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_scan
'''
import os
import sys
from calendar import monthrange
from datetime import datetime, timedelta

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_end_scan, generate_params, check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import reformat_time

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_days = ['thursday', 'wednesday', 'saturday', 'monday']
scan_times = ['9PM', '20:00', '12am', '12pm']

# configurations

p, m = generate_params(extra_params={'TEST_DIRECTORIES': directory_str, 'SCAN_DAY': scan_days, 'SCAN_TIME': scan_times},
                       modes=['scheduled'] * len(scan_days))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# functions

def replace_date(date, days):
    """
    Add a number of days to the given date and calculates if it should change the month as well.

    Parameters
    ----------
    date : datetime
        Source date to be modified
    days : int
        Number of days that will be added to `date`

    Returns
    -------
    datetime
        `date` + `days` resulting datetime
    """
    today = datetime.now()
    max_days_in_month = monthrange(today.year, today.month)[1]
    if today.day + days > max_days_in_month:
        new_day = (today.day + days) % max_days_in_month
        new_month = today.month + 1
        if new_month > 12:
            new_month = 1
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
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('tags_to_apply', [{'scan_both'}])
def test_scan_day_and_time(tags_to_apply,
                           get_configuration, configure_environment,
                           restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' performs a scan on the day of the week and the time specified in
                 the 'scan_day' and 'scan_time' tags. For this purpose, the test will monitor a testing folder and
                 modify the system date to the moment of the scan that should be performed. Then, it will check
                 if an FIM event, indicating that the scan is ended, is generated. Finally, the test will verify
                 that scans are not performed on a different day or time specified in the test case.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that an FIM event is generated when the system date matches
          the day of the week and the time specified for the scan.
        - Verify that scan is not performed on a different day or time than scheduled.

    input_description: A test case (scan_both) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon. These are combined
                       with the testing directory to be monitored and the scan dates defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (at scan ends)

    tags:
        - scheduled
        - time_travel
    '''
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
            check_time_travel(time_travel=True, interval=scan_time - current_day + timedelta(minutes=1))
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                                    error_message='Did not receive expected '
                                                  '"File integrity monitoring scan ended" event')
            return
        else:
            day_diff = 7

    if day_diff > 1:
        check_time_travel(time_travel=True, interval=timedelta(days=day_diff - 1))
        current_day = datetime.now()
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_end_scan)
            raise AttributeError(f'Unexpected event {event}')

    check_time_travel(time_travel=True, interval=scan_time - current_day - timedelta(minutes=5))
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan)
        raise AttributeError(f'Unexpected event {event}')

    check_time_travel(time_travel=True, interval=timedelta(minutes=6))
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                            error_message='Did not receive expected '
                                          '"File integrity monitoring scan ended" event')
