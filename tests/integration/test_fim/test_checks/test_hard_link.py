# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import time

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (HARDLINK, LOG_FILE_PATH, REGULAR, EventChecker,
                               check_time_travel, create_file, delete_file, modify_file_content, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_hard_link.yaml')
testdir1 = os.path.join(PREFIX, 'testdir1')
unmonitored_dir = os.path.join(PREFIX, 'test_unmonitorized')
test_directories = [testdir1, unmonitored_dir]
frequency = global_parameters.default_timeout * 3 + 2

# configurations

p, m = generate_params(extra_params={'FREQUENCY': str(frequency)},
                       apply_to_all=({'INODE': {'check_inode': inode}} for inode in ['yes', 'no']))

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=p,
                                           metadata=m
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


from wazuh_testing.fim import LOG_FILE_PATH, detect_initial_scan
from wazuh_testing.tools.services import control_service

@pytest.fixture(scope='function')
def clean_directories(request):

    directories = getattr(request.module, 'test_directories')
    for folder in directories:
        for the_file in os.listdir(folder):
            file_path = os.path.join(folder, the_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)
# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Hard links.")
@pytest.mark.parametrize('path_file, file_name, path_link, link_name, num_links', [
    (testdir1, "regular1", unmonitored_dir, "unmonitored_hardlink", 1),
    (testdir1, "regular2", testdir1, "hardlink", 2)
])
def test_hard_link(path_file, file_name, path_link, link_name, num_links, get_configuration,
                   configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Test the check_inode option when used with Hard links by creating a hard link file inside and outside the
    monitored directory.

    When a regular file with one or more hard links pointing to it is modified the event raised will have a field named
    'hard_links' that must contain a list with the path to those hard links. Only modification events for the regular
    file are expected, not for the hard links, even if we modify a hard link.

    Parameters
    ----------
    path_file : str
        The path to the regular file to be created.
    file_name : str
        The name of the regular file to be created.
    path_link : str
        The path to the Hard links to be created.
    link_name : str
        The name of the Hard links to be created.
    num_links : int
        Number of hard links to create. All of them will be pointing to the same regular file.
    """
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
                    if i == len(expected_file)-1:
                        raise
        else:
            event_checker.file_list = [expected_file]
            event_checker.check_events("modified", mode=mode)

        # Validate number of events
        assert len(event_checker.events) == 1, f"More than one 'modified' event was detected."
        event = event_checker.events[0]

        # Validate 'Hard_links' field
        if path_file == path_link:
            expected_hard_links = set(expected_hard_links)
            assert (set(event['data']['hard_links']).intersection(expected_hard_links) == set()), f"The event's hard_links "
            f"field was '{event['data']['hard_links']}' when was expected to be '{expected_hard_links}'"

    is_scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file_list = [file_name]
    hardlinks_list = list()

    event_checker = EventChecker(wazuh_log_monitor, path_file, file_list)

    # Create the regular file
    create_file(REGULAR, path_file, file_name, content='test content')
    if is_scheduled:
        time.sleep(frequency+1)
    event_checker.fetch_and_check('added', min_timeout=global_parameters.default_timeout)

    # Create as many links pointing to the regular file as num_links
    for link in range(0, num_links):
        new_link_name = "HardLink" + str(link)
        hardlinks_list.append(new_link_name)
        create_file(HARDLINK, path_link, new_link_name, target=os.path.join(path_file, file_name))

    # Detect the 'added' events for all the created links
    if path_file == path_link:
        if is_scheduled:
            time.sleep(frequency+1)
        event_checker.file_list = hardlinks_list
        event_checker.fetch_and_check('added', min_timeout=global_parameters.default_timeout)

    # Modify the regular file
    modify_file_content(path_file, file_name, new_content="modified testregularfile")
    if is_scheduled:
        time.sleep(frequency+1)

    # Only events for the regular file are expected
    event_checker.file_list = file_list
    detect_and_validate_event(expected_file=file_name,
                              mode=get_configuration['metadata']['fim_mode'],
                              expected_hard_links=hardlinks_list)

    # Modify one of the hard links
    modify_file_content(path_link, hardlinks_list[0], new_content="modified HardLink0")

    if path_file == path_link and not is_scheduled:
        detect_and_validate_event(expected_file=hardlinks_list[0],
                                  mode=get_configuration['metadata']['fim_mode'],
                                  expected_hard_links=[file_name] + hardlinks_list[1:])
    else:
        # If the link is not inside the monitored dir Scheduled run should detect the modification of the file
        # even if we are using Real-time or Whodata.
        time.sleep(frequency+1)
        detect_and_validate_event(expected_file=[file_name] + hardlinks_list,
                                  mode="scheduled",
                                  expected_hard_links=hardlinks_list)
