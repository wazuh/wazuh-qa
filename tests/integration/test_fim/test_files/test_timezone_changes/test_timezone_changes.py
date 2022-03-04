'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check that the modifications made on monitored
       files during the initial scan ('baseline') generate FIM events after that scan.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_timezone_changes

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_timezone_changes
'''
import os
import sys
import time

import pytest
from wazuh_testing.fim import (LOG_FILE_PATH, REGULAR, callback_detect_event, callback_detect_end_scan, create_file,
                               generate_params, delete_file, global_parameters, check_time_travel)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

testdir1 = os.path.join(PREFIX, 'testdir1')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_timezone_conf.yaml')

# configurations

conf_params = {'TEST_DIRECTORIES': testdir1, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def set_local_timezone():
    if sys.platform == 'win32':
        os.system('tzutil /s "Romance Standard Time"')
    else:
        os.environ['TZ'] = 'Europe/Madrid'
        time.tzset()


def set_foreign_timezone():
    if sys.platform == 'win32':
        os.system('tzutil /s "Egypt Standard Time"')
    else:
        os.environ['TZ'] = 'Asia/Tokyo'
        time.tzset()


def callback_detect_event_before_end_scan(line):
    ended_scan = callback_detect_end_scan(line)
    if ended_scan is None:
        event = callback_detect_event(line)
        assert event is None, 'Event detected before end scan'
        return None
    else:
        return True


def extra_configuration_before_yield():
    set_local_timezone()
    create_file(REGULAR, testdir1, 'regular', content='')


def extra_configuration_after_yield():
    delete_file(testdir1, 'regular')
    set_local_timezone()

def test_timezone_changes(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon' detects events when they appear after the 'baseline' scan.
                 The log message 'File integrity monitoring scan ended' informs about the end of the first scan,
                 which generates the 'baseline'. For this purpose, the test creates a test file while the initial
                 scan is being performed. When the baseline has been generated it checks if the FIM 'added' event
                 has been triggered.

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
        - Verify that an FIM 'added' event is generated after the initial scan when the related file operation
          is made before the scan ends.

    input_description: A test case (timezone_conf) is contained in external YAML file (wazuh_timezone_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is
                       combined with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' event)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'timezone_conf'}, get_configuration['tags'])

    # Change time zone
    set_foreign_timezone()

    check_time_travel(True, monitor=wazuh_log_monitor)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event_before_end_scan,
                            error_message='Did not receive expected event before end the scan')
