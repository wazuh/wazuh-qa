'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       only for file operations in monitored directories that do not match the 'restrict' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_restrict

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
    - fim_restrict
'''
import os
import sys
import pytest
from time import sleep

from wazuh_testing import global_parameters, REGULAR, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import create_file
from wazuh_testing.modules.fim.event_monitor import callback_detect_file_added_event, callback_restricted
from wazuh_testing.modules.fim.utils import generate_params


# Marks
pytestmark = pytest.mark.tier(level=1)

# Variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir1', 'subdir')
                    ]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations
conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': test_directories[0]})
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('folder', test_directories)
@pytest.mark.parametrize('filename, mode, content, triggers_event, tags_to_apply', [
    ('.restricted', 'w', "Sample content", True, {'valid_regex1'}),
    ('binary.restricted', 'wb', b"Sample content", True, {'valid_regex1'}),
    ('testfile2', 'w', "", False, {'valid_regex'}),
    ("btestfile2", "wb", b"", False, {'valid_regex'}),
    ('testfile2', 'w', "", True, {'valid_empty'}),
    ("btestfile2", "wb", b"", True, {'valid_empty'}),
    ("restricted", "w", "Test", False, {'valid_regex'}),
    ("myfilerestricted", "w", "", True, {'valid_regex_3'}),
    ("myother_restricted", "wb", b"", True, {'valid_regex_3'}),
    ('fileinfolder', 'w', "Sample content", True,
     {f'valid_regex_incomplete_{"win" if sys.platform == "win32" else "unix"}'}),
    ('fileinfolder1', 'wb', b"Sample content", True,
     {f'valid_regex_incomplete_{"win" if sys.platform == "win32" else "unix"}'}),
    ('testing_regex', 'w', "", False, {f'valid_regex_incomplete_{"win" if sys.platform == "win32" else "unix"}'}),
])
def test_restrict(folder, filename, mode, content, triggers_event, tags_to_apply, get_configuration,
                  configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or ignores events in monitored files depending
                 on the value set in the 'restrict' attribute. This attribute limit checks to files that match
                 the entered string or regex and its file name. For this purpose, the test will monitor a folder
                 and create a testing file inside it. Finally, the test will verify that FIM 'added' events are
                 generated only for the testing files that not are restricted.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - folder:
            type: str
            brief: Path to the directory where the testing file will be created.
        - filename:
            type: str
            brief: Name of the testing file to be created.
        - mode:
            type: str
            brief: Same as mode in 'open' built-in function.
        - content:
            type: str
            brief: Content to fill the testing file.
        - triggers_event:
            type: bool
            brief: True if an FIM event must be generated, False otherwise.
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
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are only generated for file operations in monitored directories
          that do not match the 'restrict' attribute.
        - Verify that FIM 'ignoring' events are generated for monitored files that are restricted.

    input_description: Different test cases are contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directories to be monitored defined in the module.

    inputs: 864 test cases including multiple regular expressions and names for testing files and directories.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Ignoring entry .* due to restriction .*'

    tags:
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create text files
    create_file(REGULAR, folder, filename, content=content)

    # Go ahead in time to let syscheck perform a new scan
    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        sleep(3)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_file_added_event).result()
        assert event['data']['path'] == os.path.join(folder, filename), f'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                   callback=callback_restricted,
                                                   error_message='Did not receive expected '
                                                                 '"Sending FIM event: ..." event').result()
            if ignored_file == os.path.join(folder, filename):
                break
