'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if the 'ignore' tag
       works correctly when environment variables are used to define the directories to ignore.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_env_variables

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
    - fim_env_variables
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_event, callback_ignore, create_file,
                               REGULAR, generate_params, check_time_travel)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'),
                    os.path.join(PREFIX, 'testdir4')
                    ]
dir1, dir2, dir3, dir4 = test_directories

# Check big environment variables ending with backslash
if sys.platform == 'win32':
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(10)] + [dir2, dir3]
    test_env = "%TEST_IGN_ENV%"
else:
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(100)] + [dir2, dir3]
    test_env = "$TEST_IGN_ENV"

multiple_env_var = os.pathsep.join(paths)
environment_variables = [("TEST_IGN_ENV", multiple_env_var)]

dir_config = ",".join(test_directories)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_ignore.yaml')

conf_params = {'TEST_DIRECTORIES': dir_config, 'TEST_ENV_VARIABLES': test_env, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory, event_generated', [
    (dir1, True),
    (dir2, False),
    (dir3, False),
    (dir4, True),
])
@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_tag_ignore(directory, event_generated, get_configuration, configure_environment, put_env_variables,
                    restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon ignores directories when they are defined using
                 environment variables. For this purpose, the test will monitor a directory that is ignored
                 in an environment variable set in the 'ignore' tag. Then, a testing file will be added to
                 that directory, and finally, the test will verify that the 'ignoring' or `added` FIM events
                 have been generated according to the test case.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - directory:
            type: str
            brief: Path to the directory to be monitored.
        - event_generated:
            type: bool
            brief: True if the directory is not ignored. False otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - put_env_variables:
            type: fixture
            brief: Create the environment variables.
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
        - Verify that 'ignoring' FIM event is generated when the ignored directories
          are defined using environment variables.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf_ignore.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, it is combined
                       with the directories to be ignored defined as environment variables in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' event if the testing directory is not ignored)
        - r'.*Ignoring'

    tags:
        - scheduled
        - time_travel
    '''
    # Create text files
    filename = "test"
    create_file(REGULAR, directory, filename, content="")

    # Go ahead in time to let syscheck perform a new scan
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if event_generated:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(directory, filename), 'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                   callback=callback_ignore).result()
            if ignored_file == os.path.join(directory, filename):
                break
