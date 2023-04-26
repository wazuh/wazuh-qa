'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if the 'wazuh-syscheckd' daemon runs
       the scans on a specific day of the week set in the 'scan_day' tag.
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
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#scan-day

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
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('tags_to_apply', [{'scan_day'}])
def test_scan_day(tags_to_apply,
                  get_configuration, configure_environment,
                  restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' performs a scan on the day of the week specified in
                 the 'scan_day' tag. For this purpose, the test will monitor a testing folder and
                 modify the system date to the day of the scan that should be performed. Then, it
                 will check if an FIM event, indicating that the scan is ended, is generated. Finally,
                 the test will verify that scans are not performed on a different day of the week
                 specified in the test case.

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
          the day of the week specified for the scan.
        - Verify that scan is not performed on a different day of the week than scheduled.

    input_description: A test case (scan_day) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon. These are combined
                       with the testing directory to be monitored and the scan days defined in the module.

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
