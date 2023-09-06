'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if the 'nodiff' tag works correctly
       when environment variables are used to define the files whose changes will not be tracked.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks  configured
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
    - macos

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff

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
from test_fim.common import make_diff_file_path
from wazuh_testing import global_parameters, LOG_FILE_PATH
from wazuh_testing.modules.fim.utils import regular_file_cud, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, PREFIX
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
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(10)] + \
            [os.path.join(dir2, "test.txt"), os.path.join(dir3, "test.txt")]
    test_env = "%TEST_NODIFF_ENV%"
else:
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(100)] + \
            [os.path.join(dir2, "test.txt"), os.path.join(dir3, "test.txt")]
    test_env = "$TEST_NODIFF_ENV"

multiple_env_var = os.pathsep.join(paths)
environment_variables = [("TEST_NODIFF_ENV", multiple_env_var)]

dir_config = ",".join(test_directories)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_nodiff.yaml')
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")

conf_params = {'TEST_DIRECTORIES': dir_config, 'TEST_ENV_VARIABLES': test_env, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory, filename, hidden_content', [
    (dir1, "testing.txt", False),
    (dir2, "test.txt", True),
    (dir3, "test.txt", True),
    (dir4, "testing.txt", False),
])
@mark_skip_agentWindows
def test_tag_nodiff(directory, filename, hidden_content, get_configuration, put_env_variables, configure_environment,
                    restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon truncates the content in the 'diff' files when testing files
                 are defined using environment variables via the 'nodiff' tag. For this purpose, the test will monitor
                 a directory using the 'report_changes=yes' attribute and some testing files will be defined in
                 the 'nodiff' tag using environment variables. Then, it will perform operations on the testing files
                 and check if the corresponding diff files have been created. Finally, the test will verify that
                 the 'diff' files of the testing files set in the 'nodiff' tag have their content truncated.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - directory:
            type: str
            brief: Path to the directory to be monitored.
        - filename:
            type: str
            brief: Name of the testing file to be tracked.
        - hidden_content:
            type: bool
            brief: True if the 'diff' file must not be created. False otherwise.
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
        - Verify that the 'content_changes' field of FIM events has a message
          indicating that the 'nodiff' option is being used.
        - Verify that 'diff' files are its content truncated when files are specified
          via environment variables using the 'nodiff' tag.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf_nodiff.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, it is combined
                       with the directories and testing files defined as environment variables in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)
        - The 'diff' file in the default location.

    tags:
        - scheduled
        - time_travel
    '''
    files = {filename: b'Hello word!'}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for file in files:
            diff_file = make_diff_file_path(directory, file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if hidden_content:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'

    regular_file_cud(directory, wazuh_log_monitor, file_list=files,
                     min_timeout=global_parameters.default_timeout*2, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
