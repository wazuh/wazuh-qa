# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing.fim import (HARDLINK, LOG_FILE_PATH, REGULAR, EventChecker,
                               check_time_travel, create_file, delete_file, modify_file_content, generate_params)
from wazuh_testing import global_parameters
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_hard_link.yaml')
testdir1 = os.path.join('/', 'testdir1')
unmonitored_dir = os.path.join('/', 'test_unmonitorized')
test_directories = [testdir1, unmonitored_dir]


# configurations

p, m = generate_params(apply_to_all=({'INODE': {'check_inode': inode}} for inode in ['yes', 'no']))

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
@pytest.mark.parametrize('path_file, path_link, num_links', [
    (testdir1, unmonitored_dir, 1),
    (testdir1, testdir1, 2)
])
def test_hard_link(path_file, path_link, num_links, get_configuration,
                   configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Test the check_inode option when used with Hard links by creating a hard link file inside and outside the
    monitored directory.

    Parameters
    ----------
    path_file : str
        The path to the regular file to be created.
    path_link: str
        The path to the Hard links to be created.
    num_links : int
        Number of hard links to create. All of them will be pointing to the same regular file.
    """
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    is_scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    regular_file_name = "testregularfile"
    file_list = [regular_file_name]
    hardlinks_list = []

    event_checker = EventChecker(wazuh_log_monitor, path_file, file_list)

    # Create the regular file
    create_file(REGULAR, path_file, regular_file_name, content='test content')
    check_time_travel(is_scheduled)
    event_checker.fetch_and_check('added', min_timeout=global_parameters.default_timeout)

    # Create as many links pointing to the regular file as num_links
    for link in range(0, num_links):
        hardlinks_list.append("HardLink" + str(link))
        create_file(HARDLINK, path_link, "HardLink" + str(link), target=os.path.join(path_file, regular_file_name))

    # Try to detect the creation events for all the created links
    if path_file == path_link:
        check_time_travel(is_scheduled)
        event_checker.file_list = hardlinks_list
        event_checker.fetch_and_check('added', min_timeout=global_parameters.default_timeout)

    # Update file_list with the links if these were created in the monitored folder
    event_checker.file_list = file_list + hardlinks_list if path_file == path_link else file_list

    # Modify the original file and detect the events for the entire file_list
    modify_file_content(path_file, regular_file_name, new_content="modified testregularfile")
    check_time_travel(is_scheduled)
    event_checker.fetch_and_check('modified', min_timeout=global_parameters.default_timeout)

    # Modify one of the hard links
    modify_file_content(path_link, "HardLink0", new_content="modified HardLink0")

    # If the hard link is inside the monitored dir alerts should be triggered for the entire file_list
    # Scheduled run should ALWAYS detect the modification of the file, even if we are using Real-time or Whodata.
    check_time_travel(path_file != path_link or is_scheduled)
    event_checker.fetch_and_check('modified', min_timeout=global_parameters.default_timeout)

    # Clean up
    delete_file(path_file, regular_file_name)
    for link in hardlinks_list:
        delete_file(path_link, link)
    check_time_travel(True)
    event_checker.fetch_and_check('deleted', min_timeout=global_parameters.default_timeout)
