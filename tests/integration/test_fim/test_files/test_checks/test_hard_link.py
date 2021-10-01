'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM events are generated when 'hard links'
       of a monitored file are modified but are located in a different directory than the source file.
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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
    - https://en.wikipedia.org/wiki/Inode

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_checks
'''
import os
import sys
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (HARDLINK, LOG_FILE_PATH, REGULAR, EventChecker,
                               check_time_travel, create_file, modify_file_content, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_hard_link.yaml')
testdir1 = os.path.join(PREFIX, 'testdir1')
unmonitored_dir = os.path.join(PREFIX, 'test_unmonitorized')
test_directories = [testdir1, unmonitored_dir]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

p, m = generate_params(apply_to_all=({'INODE': {'check_inode': inode}} for inode in ['yes', 'no']), modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=p,
                                           metadata=m
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Hard links.")
@pytest.mark.parametrize('path_file, file_name, path_link, link_name, num_links', [
    (testdir1, "regular1", unmonitored_dir, "unmonitored_hardlink", 1),
    (testdir1, "regular2", testdir1, "hardlink", 2)
])
def test_hard_link(path_file, file_name, path_link, link_name, num_links, get_configuration,
                   configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when the 'check_inode' attribute is used
                 and 'hard links' are modified while inside and outside the monitored directory.
                 When a regular file with one or more hard links pointing to it is modified, the FIM event
                 raised will have a field named 'hard_links' that must contain a list with the path to those
                 'hard links'. Only modification events for the regular file are expected, not for the 'hard links'
                 even if the 'hard link' is modified. For this purpose, the test will monitor a directory where
                 it will add a testing file, create several 'hard links' pointing to it and verify that these
                 operations have generated the appropriate FIM 'added' events. Then it will modify the testing file
                 and check if the 'modified' events have been generated for that file only. Finally, the test
                 will verify that appropriate FIM events are generated if one of the 'hard links'
                 within the monitored directory is modified.

    wazuh_min_version: 4.2.0

    parameters:
        - path_file:
            type: str
            brief: Path to the regular file to be created.
        - file_name:
            type: str
            brief: Name of the regular file to be created.
        - path_link:
            type: str
            brief: Path to the 'hard links' to be created.
        - link_name:
            type: str
            brief: Name of the 'hard links' to be created.
        - num_links:
            type: int
            brief: Number of hard links to create. All of them will be pointing to the same regular file.
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
        - Verify that the FIM events generated contain contain the proper number of 'hard links'
          in the 'hard_links' field.
        - Verify that only FIM events are generated when the regular file being monitored is modified.

    input_description: A test case (test_hard_link) is contained in external YAML file
                       (wazuh_hard_link.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and testing directory to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    def detect_and_validate_event(expected_file, mode, expected_hard_links):
        event_checker.events = event_checker.fetch_events(min_timeout=global_parameters.default_timeout)

        # Check if the event's path is the expected one
        if isinstance(expected_file, list):
            for i in range(0, len(expected_file)):
                try:
                    event_checker.file_list = [expected_file[i]]
                    event_checker.check_events("modified", mode=mode)
                    break
                except AssertionError:
                    if i == len(expected_file) - 1:
                        raise
        else:
            event_checker.file_list = [expected_file]
            event_checker.check_events("modified", mode=mode)

        # Validate number of events
        assert len(event_checker.events) == 1, "More than one 'modified' event was detected."
        event = event_checker.events[0]

        # Validate 'Hard_links' field
        if path_file == path_link:
            expected_hard_links = set(expected_hard_links)
            assert (set(event['data']['hard_links']).intersection(expected_hard_links) == set()), "The event's "
            f"'hard_links' field was '{event['data']['hard_links']}' when was expected to be '{expected_hard_links}'"

    file_list = [file_name]
    hardlinks_list = list()

    event_checker = EventChecker(wazuh_log_monitor, path_file, file_list)

    # Create the regular file
    create_file(REGULAR, path_file, file_name, content='test content')
    check_time_travel(True, monitor=wazuh_log_monitor)
    event_checker.fetch_and_check('added', min_timeout=global_parameters.default_timeout)

    # Create as many links pointing to the regular file as num_links
    for link in range(0, num_links):
        new_link_name = "HardLink" + str(link)
        hardlinks_list.append(new_link_name)
        create_file(HARDLINK, path_link, new_link_name, target=os.path.join(path_file, file_name))

    # Detect the 'added' events for all the created links
    if path_file == path_link:
        check_time_travel(True, monitor=wazuh_log_monitor)
        event_checker.file_list = hardlinks_list
        event_checker.fetch_and_check('added', min_timeout=global_parameters.default_timeout)

    # Modify the regular file
    modify_file_content(path_file, file_name, new_content="modified testregularfile")
    check_time_travel(True, monitor=wazuh_log_monitor)

    # Expect an event for the regular file or one of the hard links if the links are in the monitored dir and mode
    # is scheduled. Expect an event for the regular file only otherwise.
    event_checker.file_list = file_list
    expected_file = [file_name] + hardlinks_list if path_file == path_link else file_name
    detect_and_validate_event(expected_file=expected_file,
                              mode=get_configuration['metadata']['fim_mode'],
                              expected_hard_links=hardlinks_list)

    time.sleep(1)
    # Modify one of the hard links
    modify_file_content(path_link, hardlinks_list[0], new_content="modified HardLink0")

    check_time_travel(True, monitor=wazuh_log_monitor)
    detect_and_validate_event(expected_file=[file_name] + hardlinks_list,
                              mode="scheduled",
                              expected_hard_links=hardlinks_list)
