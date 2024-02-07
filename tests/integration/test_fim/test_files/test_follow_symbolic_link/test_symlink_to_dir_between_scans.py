'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will verify that FIM monitors a new directory when
       a monitored 'symbolic link' is replaced by it, and the 'follow_symbolic_link' attribute is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_follow_symbolic_link

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - macos
    - solaris

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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_follow_symbolic_link
'''
import os
from shutil import rmtree

import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import wait_for_symlink_check, symlink_interval, \
    testdir_link, testdir_target
from wazuh_testing import global_parameters

from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'}, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Create files and symlinks"""
    symlinkdir = testdir_link

    os.makedirs(testdir_target, exist_ok=True, mode=0o777)
    fim.create_file(fim.REGULAR, testdir_target, 'regular1')
    fim.create_file(fim.SYMLINK, PREFIX, symlinkdir, target=testdir_target)
    # Set symlink_scan_interval to a given value
    fim.change_internal_options(param='syscheck.symlink_scan_interval', value=symlink_interval)


def extra_configuration_after_yield():
    """Set symlink_scan_interval to default value"""
    rmtree(testdir_link, ignore_errors=True)
    rmtree(testdir_target, ignore_errors=True)
    fim.change_internal_options(param='syscheck.symlink_scan_interval', value=600)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'replace_with_directory'},
])
def test_symlink_to_dir_between_scans(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                      wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when a monitored symlink is replaced by
                 a directory between scans, and the 'follow_symbolic_link' setting is used. For this purpose,
                 the test will create a directory with some files and a 'symbolic link'. Then, it will remove
                 the link and create a directory with the same path. Finally, it will wait until the next
                 scheduled scan and verify that FIM events are generated by adding new files.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
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
        - Verify that FIM events are generated from a new directory when a monitored 'symbolic link'
          is replaced by it, and the 'follow_symbolic_link' setting is used.

    input_description: A test case (replace_with_directory) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the common.py module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    regular2 = 'regular2'

    # Delete symbolic link and create a folder with the same name
    os.remove(testdir_link)
    os.makedirs(testdir_link, exist_ok=True, mode=0o777)
    fim.create_file(fim.REGULAR, testdir_link, regular2)

    # Wait for both audit and the symlink check to run
    wait_for_symlink_check(wazuh_log_monitor)
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)

    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                    error_message='Did not receive expected '
                                                  '"Sending FIM event: ..." event').result()

    assert 'added' in event['data']['type'] and regular2 in event['data']['path'], \
        f'"added" event not matching for {event}'