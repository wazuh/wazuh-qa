'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM detects invalid
       values for the 'interval' tag of the 'synchronization' feature.
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
from wazuh_testing.fim import LOG_FILE_PATH, callback_configuration_warning
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_invalid_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_invalid_sync_response(get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects invalid synchronization intervals
                 by catching the warning message displayed on the log file. For this purpose,
                 the test will monitor a testing directory and setup the 'synchronization' option
                 using invalid values for its 'interval' tag. Finally, it will verify that the FIM
                 'warning' event has been generated, indicating that an invalid value is used.

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

    assertions:
        - Verify that FIM 'warning' event is generated when using an invalid value
          for the interval tag of the 'synchronization' option.

    input_description: A test case (sync_invalid) is contained in external YAML file (wazuh_invalid_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*WARNING:.* Invalid value for element'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'sync_invalid'}, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_configuration_warning,
                            error_message='Did not receive expected '
                                          '"WARNING: ...: Invalid value for element" event')
