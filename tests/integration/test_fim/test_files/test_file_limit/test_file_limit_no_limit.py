'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if the FIM event 'no limit'
       is generated when the 'file_limit' feature is disabled in the configuration.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-limit

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_file_limit
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_file_limit_zero, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")

# Configurations

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1})

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('tags_to_apply', [
    {'no_file_limit'}
])
@mark_skip_agentWindows
def test_file_limit_no_limit(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects that the 'file_limit' feature of FIM is disabled.
                 For this purpose, the test will monitor a testing directory, and finally, it will verify
                 that the FIM event 'no limit' is generated.

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
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the FIM event 'no limit' is generated when the 'file_limit' feature is disabled.

    input_description: A test case (no_file_limit) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is
                       combined with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*No limit set to maximum number of entries to be monitored'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_file_limit_zero,
                            error_message='Did not receive expected "DEBUG: ...: '
                                          'No limit set to maximum number of entries to be monitored" event')
