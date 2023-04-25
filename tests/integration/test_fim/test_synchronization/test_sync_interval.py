'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM synchronizes the database on
       Linux systems at the period specified in the 'interval' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: synchronization

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux

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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_synchronization, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine, time_to_timedelta

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
sync_intervals = ['10', '10s', '10m', '10h', '10d', '10w']

# configurations

p, m = generate_params(apply_to_all=({'INTERVAL': sync_interval} for sync_interval in sync_intervals),
                       modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
@pytest.mark.skip(reason="It will be blocked by #3992, when it was solve we can enable again this test")
def test_sync_interval(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon performs the file synchronization at the intervals
                 specified in the configuration, using the 'interval' tag. For this purpose, the test
                 will monitor a testing directory. Then, it will travel in time to the next synchronization
                 time and verify that the FIM 'integrity' event is trigered. Finally, the test will travel
                 in time to half of the interval and verify that no FIM 'integrity' event is generated.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
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
        - Verify that FIM 'integrity' event is generated when the interval specified has elapsed.
        - Verify that no FIM 'integrity' event is generated at half of the interval specified.

    input_description: A test case (sync_interval) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the interval periods and the testing directory to be monitored defined in this module.

    expected_output:
        - r'Initializing FIM Integrity Synchronization check'

    tags:
        - scheduled
        - time_travel
    '''
    # Check if the test should be skipped
    check_apply_test({'sync_interval'}, get_configuration['tags'])
    interval = time_to_timedelta(get_configuration['metadata']['interval'])

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_synchronization,
                            error_message='Did not receive expected '
                                          '"Initializing FIM Integrity Synchronization check" event')

    TimeMachine.travel_to_future(interval)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_synchronization,
                            error_message='Did not receive expected '
                                          '"Initializing FIM Integrity Synchronization check" event')

    # This should fail as we are only advancing half the time needed for synchronization to occur
    TimeMachine.travel_to_future(interval / 2)
    try:
        result = wazuh_log_monitor.start(timeout=1 if interval.total_seconds() == 10.0 else 3,
                                         callback=callback_detect_synchronization,
                                         accum_results=1,
                                         error_message='Did not receive expected "Initializing FIM Integrity '
                                                       'Synchronization check" event').result()
        if result is not None:
            pytest.fail("Synchronization shouldn't happen at this point")
    except TimeoutError:
        return
