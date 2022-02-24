'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will verify that FIM follows the precedence in
       the configuration when a directory is monitored inside a monitored 'symbolic link', and
       the 'follow_symbolic_link' attribute is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
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
    - macOS Catalina
    - Solaris 10
    - Solaris 11

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

import pytest
import wazuh_testing.fim as fim

from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# Variables

test_directories = [os.path.join(PREFIX, 'testdir')]
testdir = test_directories[0]
testdir_link = os.path.join(PREFIX, 'testdir_link')
testdir_target = os.path.join(testdir, 'testdir_target')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'})
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Create files and symlinks"""
    os.makedirs(testdir_target, exist_ok=True, mode=0o777)
    fim.create_file(fim.REGULAR, testdir_target, 'regular1')
    fim.create_file(fim.SYMLINK, PREFIX, 'testdir_link', target=testdir_target)


def extra_configuration_after_yield():
    """Set symlink_scan_interval to default value"""
    os.remove(testdir_link)


# Tests

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply, checkers', [
    ({'symlink_dir_inside_monitored_dir'}, fim.REQUIRED_ATTRIBUTES[fim.CHECK_ALL] - {fim.CHECK_SIZE}),
])
def test_symlink_dir_inside_monitored_dir(tags_to_apply, checkers, get_configuration, configure_environment,
                                          restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the precedence in the configuration when monitoring a
                 subdirectory from a symlink having a different configuration, and the 'follow_symbolic_link' setting
                 is used. The monitored directory configuration should prevail over the symlink configuration
                 (checks, follow_symbolic_link, etc.). For this purpose, the test will create a directory, a
                 'symbolic link' to that directory, and a subdirectory. The directory and the symlink will be
                 monitored using different options. Then, the test will make file operations inside the directory
                 and check if the FIM events fields match the ones configured for the 'symbolic link'. Finally,
                 it will make file operations in the subdirectory and verify that the FIM events fields match
                 the ones configured for the link.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - checkers:
            type: dict
            brief: Check options to be used.
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
        - Verify that FIM follows the precedence in the configuration when monitoring a subdirectory from
          a 'symbolic link' having a different configuration, and the 'follow_symbolic_link' setting is used.

    input_description: A test case (symlink_dir_inside_monitored_dir) is contained in external YAML file
                       (wazuh_conf.yaml) which includes configuration settings for the 'wazuh-syscheckd' daemon and,
                       these are combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Alerts from the pointed directory should have all checks except size
    fim.regular_file_cud(testdir_target, wazuh_log_monitor,
                         min_timeout=global_parameters.default_timeout, options=checkers, time_travel=scheduled)
    # Alerts from the main directory should have all checks
    fim.regular_file_cud(testdir, wazuh_log_monitor,
                         min_timeout=global_parameters.default_timeout, time_travel=scheduled)
