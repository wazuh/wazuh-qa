'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM detects
       invalid configurations and indicates the location of the errors detected.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

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
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#ignore

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_invalid
'''
import os
import sys

import pytest
from wazuh_testing.fim import LOG_FILE_PATH, callback_configuration_error
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'TEST_DIRECTORIES': directory_str}],
                                           metadata=[{'test_directories': directory_str}]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    ({'invalid_no_regex', 'invalid_scan', 'invalid_file_limit'})
])
def test_invalid(tags_to_apply, get_configuration, configure_environment):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects invalid configurations. For this purpose, the test
                 will configure 'syscheck' using invalid configuration settings with different attributes. Finally,
                 it will verify that error events are generated indicating the source of the errors.

    wazuh_min_version: 4.2.0

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

    assertions:
        - Verify that FIM raises a 'ValueError' when an invalid configuration is used
          and the testing platform is not Windows.
        - Verify that an FIM error event is generated when an invalid configuration is detected.

    input_description: Different test cases are contained in external YAML files (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Configuration error at'

    tags:
        - realtime
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    # Configuration error -> ValueError raised
    try:
        control_service('restart')
    except ValueError:
        assert sys.platform != 'win32', 'Restarting ossec with invalid configuration should ' \
                                        'not raise an exception in win32'

    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error,
                            error_message='Did not receive expected '
                                          '"CRITICAL: ...: Configuration error at" event')
