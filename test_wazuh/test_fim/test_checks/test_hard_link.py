# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from copy import deepcopy

import pytest
from wazuh_testing.fim import (DEFAULT_TIMEOUT, HARDLINK, LOG_FILE_PATH, REGULAR, EventChecker,
                               check_time_travel, create_file, delete_file, modify_file_content, generate_params)
from wazuh_testing.tools import FileMonitor, load_wazuh_configurations, truncate_file

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_hard_link.yaml')
testdir1 = os.path.join('/', 'testdir1')
unmonitored_dir = os.path.join('/', 'test_unmonitorized')
test_directories = [testdir1, unmonitored_dir]


# configurations

p, m = generate_params()

params, metadata = list(), list()
for check_inode in [{'check_inode': 'yes'}, {'check_inode': 'no'}]:
    for p_dict, m_dict in zip(p, m):
        p_dict['INODE'] = check_inode
        m_dict['inode'] = check_inode
        params.append(deepcopy(p_dict))
        metadata.append(deepcopy(m_dict))

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params,
                                           metadata=metadata
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
    """Test the check_inode option when used with Hard links by creating a hard link file inside and outside the
    monitored directory.

    This test is intended to be used with valid configurations files. Each execution of this test will configure the
    environment properly, restart the service and wait for the initial scan.

    :param path_file: The path to the regular file to be created
    :param path_link: The path to the Hard links to be created
    :param num_links: Number of hard links to create. All of them will be pointing to the same regular file.
    :param checkers: Dict with all the check options to be used
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
    event_checker.fetch_and_check('added', min_timeout=DEFAULT_TIMEOUT)

    # Create as many links pointing to the regular file as num_links
    for link in range(0, num_links):
        hardlinks_list.append("HardLink" + str(link))
        create_file(HARDLINK, path_link, "HardLink" + str(link), target=os.path.join(path_file, regular_file_name))

    # Try to detect the creation events for all the created links
    if path_file == path_link:
        check_time_travel(is_scheduled)
        event_checker.file_list = hardlinks_list
        event_checker.fetch_and_check('added', min_timeout=DEFAULT_TIMEOUT)

    # Update file_list with the links if these were created in the monitored folder
    event_checker.file_list = file_list + hardlinks_list if path_file == path_link else file_list

    # Modify the original file and detect the events for the entire file_list
    modify_file_content(path_file, regular_file_name, new_content="modified testregularfile")
    check_time_travel(is_scheduled)
    event_checker.fetch_and_check('modified', min_timeout=DEFAULT_TIMEOUT)

    # Modify one of the hard links
    modify_file_content(path_link, "HardLink0", new_content="modified HardLink0")

    # If the hard link is inside the monitored dir alerts should be triggered for the entire file_list
    # Scheduled run should ALWAYS detect the modification of the file, even if we are using Real-time or Whodata.
    check_time_travel(path_file != path_link or is_scheduled)
    event_checker.fetch_and_check('modified', min_timeout=DEFAULT_TIMEOUT)

    # Clean up
    delete_file(path_file, regular_file_name)
    for link in hardlinks_list:
        delete_file(path_link, link)
    check_time_travel(True)
    event_checker.fetch_and_check('deleted', min_timeout=DEFAULT_TIMEOUT)
