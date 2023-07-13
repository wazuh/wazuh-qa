'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if the maximum
       number of files monitored by the 'wazuh-syscheckd' daemon is set to default when
       the 'file_limit' tag is missing in the configuration.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_file_limit

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
from wazuh_testing import global_parameters, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (ERR_MSG_FILE_LIMIT_VALUES, CB_FILE_LIMIT_VALUE,
                                                     ERR_MSG_WRONG_FILE_LIMIT_VALUE)
from wazuh_testing.modules.fim.utils import generate_params

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]
NUM_FILES = 100000

# Configurations

params, metadata = generate_params(extra_params={"TEST_DIRECTORIES": testdir1})

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_file_limit_default(configure_local_internal_options_module, get_configuration, configure_environment,
                            restart_syscheckd):
    '''
    description: Check if the maximum number of files monitored by the 'wazuh-syscheckd' daemon is set to default
                 when the 'file_limit' tag is missing in the configuration. For this purpose, the test will monitor
                 a directory and wait for FIM to start and generate an event indicating the maximum number of files
                 to monitor. Finally, the test will verify that this number matches the default value (100000).

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Set the local_internal_options for the test.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the Wazuh logs file and start a new monitor.

    assertions:
        - Verify that an FIM event is generated indicating the maximum number of files
          to monitor is the default value (100000).

    input_description: A test case (file_limit_default) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is
                       combined with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*Maximum number of files to be monitored'

    tags:
        - scheduled
        - realtime
        - who_data
    '''
    # Check the file limit configured and that it matches expected value (100000)
    file_limit_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=generate_monitoring_callback(CB_FILE_LIMIT_VALUE),
                                               error_message=ERR_MSG_FILE_LIMIT_VALUES).result()

    assert file_limit_value == str(NUM_FILES), ERR_MSG_WRONG_FILE_LIMIT_VALUE
