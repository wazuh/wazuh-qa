'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the File Integrity Monitoring (`FIM`) system watches selected files
       and triggering alerts when these files are modified. All these tests will be performed using
       ambiguous directory configurations, such as directories and subdirectories with opposite
       monitoring settings. In particular, it will be verified that the value of the `ignore` attribute
       prevails over the `restrict` one.
       The `FIM` capability is managed by the `wazuh-syscheckd` daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-agentd
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2016
    - Windows server 2012
    - Windows server 2003

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time/continuous monitoring on Linux (using the inotify system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the who-data information.

tags:
    - fim
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing import logger
from wazuh_testing.fim import LOG_FILE_PATH, callback_ignore, callback_detect_event, create_file, REGULAR, \
    generate_params, check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(
    test_data_path, 'wazuh_conf_ignore_restrict_win32.yaml'
    if sys.platform == 'win32' else 'wazuh_conf_ignore_restrict.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
testdir1, testdir2 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations

conf_params, conf_metadata = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('folder, filename, triggers_event, tags_to_apply', [
    (testdir1, 'testfile', False, {'valid_no_regex'}),
    (testdir2, 'not_ignored_string', True, {'valid_no_regex'}),
    (testdir1, 'testfile2', False, {'valid_regex'}),
    (testdir1, 'ignore_testfile2', False, {'valid_regex'}),
    (testdir2, 'not_ignored_sregex', True, {'valid_regex'})
])
def test_ignore_works_over_restrict(folder, filename, triggers_event, tags_to_apply, get_configuration,
                                    configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the `ignore` tag prevails over the `restrict` one when using both in the same directory.
                 For example, when a directory is ignored and at the same time monitoring is restricted to a file
                 that is in that directory, no `FIM` events should be generated when that file is modified.
                 For this purpose, the test case configuration is applied, and it is checked if `FIM` events
                 are generated when required.

    wazuh_min_version: 4.2

    parameters:
        - folder:
            type: str
            brief: Directory where the file is being created.
        - filename:
            type: str
            brief: Name of the file to be created.
        - triggers_event:
            type: bool
            brief: True if an event must be generated, False otherwise.
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
            brief: Clear the `ossec.log` file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that when a directory is ignored, the `restrict` attribute
          is not taken into account to generate `FIM` events.

    input_description: Two test cases are contained in external `YAML` file
                       (wazuh_conf_ignore_restrict.yaml or wazuh_conf_ignore_restrict_win32.yaml)
                       which includes configuration settings for the `wazuh-syscheckd` daemon
                       and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (When the FIM event should be generated)
        - r".*Ignoring '.*?' '(.*?)' due to( sregex)? '.*?'" (When the FIM event should be ignored)

    tags:
        - scheduled
        - time_travel
    '''
    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create file that must be ignored
    logger.info(f'Adding file {os.path.join(testdir1, filename)}, content: ""')
    create_file(REGULAR, folder, filename, content='')

    # Go ahead in time to let syscheck perform a new scan if mode is scheduled
    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if triggers_event:
        logger.info('Checking the event...')
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message=f'Did not receive expected "Sending FIM event" '
                                                      f'event for file {os.path.join(testdir1, filename)}').result()

        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(folder, filename), 'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_ignore,
                                                   error_message=f'Did not receive expected '
                                                                 f'"Ignoring ... due to ..." event for file '
                                                                 f'{os.path.join(testdir1, filename)}').result()

            if ignored_file == os.path.join(folder, filename):
                break
