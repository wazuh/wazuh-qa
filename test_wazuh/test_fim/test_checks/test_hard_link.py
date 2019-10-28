# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, EventChecker, check_time_travel, create_file, modify_file_content, delete_file, REGULAR, HARDLINK)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_hard_link.yaml')
testdir1 = os.path.join('/', 'testdir1')
test_directories = [testdir1]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': ''},
                                                   {'FIM_MODE': {'realtime': 'yes'}},
                                                   {'FIM_MODE': {'whodata': 'yes'}}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled'},
                                                     {'fim_mode': 'realtime'},
                                                     {'fim_mode': 'whodata'}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('path_file, path_link, num_links', [
    (testdir1, "/", 1)
    #(testdir1, testdir1, 2),
])
def test_hard_link(path_file, path_link, num_links, get_configuration, 
                   configure_environment, restart_syscheckd, wait_for_initial_scan):
    """ 
    """

    try:
        #check_apply_test({'test_hard_link'}, get_configuration['tags'])

        # Create the regular file to which the hard links will point
        regular_file_name = "testregularfile"
        create_file(REGULAR, path_file, regular_file_name, content='test content')

        check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled')

        file_list = [regular_file_name]
        event_checker = EventChecker(wazuh_log_monitor, path_file, file_list)
        event_checker.fetch_and_check('added', min_timeout=2)


        # Create as many links as num_links in path_link pointing to regular_file_name
        hardlinks_list = []
        for link in range(0, num_links):
            hardlinks_list.append("HardLink"+str(link))
            create_file(HARDLINK, path_file, regular_file_name, content=os.path.join(path_link, "HardLink"+str(link)))
            #create_file(HARDLINK, path_link, "HardLink"+str(link), content=os.path.join(path_file, "testregularfile"))

        # Look for the creation events for all the links created
        if path_file == path_link:
            check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled')
            event_checker.file_list = hardlinks_list
            event_checker.fetch_and_check('added', min_timeout=3)

        # Modify the original file
        event_checker.file_list = file_list
        modify_file_content(path_file, regular_file_name, new_content="modified testregularfile")
        check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled')
        event_checker.fetch_and_check('modified', min_timeout=3)

        # Modify one of the hard links
        file_list = file_list + hardlinks_list if path_file == path_link else file_list
        modify_file_content(path_link, "HardLink0", new_content="modified HardLink0")
        check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled')
        event_checker.fetch_and_check('modified', min_timeout=3)

    finally:
        # Clean up
        delete_file(path_file, regular_file_name)
        for link in hardlinks_list:
            delete_file(path_link, link)
