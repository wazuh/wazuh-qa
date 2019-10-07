# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, regular_file_cud)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir'),
                    os.path.join('/', 'testdir1', 'ignore_this'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_nodiff, testdir2, testdir2_sub = test_directories

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


@pytest.mark.parametrize('folder, filename, content, hidden_content, tags_to_apply', [
    (testdir1, 'testfile', "Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'btestfile', b"Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'testfile2', "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2.nodiff", b"", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir1, "btestfile2.nodiffd", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile', "Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'btestfile', b"Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile2', "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, "btestfile2", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, ".nodiff.btestfile", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.nodiff", b"other content", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2, "another.nodiffd", b"other content", False, {'valid_regex'}),
    (testdir2_sub, "another.nodiff", b"other content", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2_sub, "another.nodiffd", b"other content", False, {'valid_regex'}),
    (testdir2, "another.nodiffd2", "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.nodiff2", "", True, {'valid_regex2', 'valid_regex3'}),
    (testdir1, 'nodiff_prefix_test.txt', "test", False,
     {'valid_regex1', 'valid_regex2', 'valid_regex3', 'valid_regex4'}),
    (testdir1, 'nodiff_prefix_test.txt', "test", True, {'valid_regex5'}),
    (testdir1, 'whatever.txt', "test", True, {'valid_empty'}),
    (testdir2, 'whatever2.txt', "test", True, {'valid_empty'})
])
def test_no_diff_subdirectory(folder, filename, content, hidden_content,
                              tags_to_apply, get_configuration,
                              configure_environment, restart_wazuh,
                              wait_for_initial_scan):
    """Checks files are ignored in subdirectory according to configuration

       This test is intended to be used with valid nodiff configurations

       :param folder string Directory where the file is being created
       :param filename string Name of the file to be created
       :param mode string same as mode in open built-in function
       :param content string, bytes Content to fill the new file
       :param hidden_content bool True if an event must be generated, False otherwise
       :param tags_to_apply set Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    time_travel = False
    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        # Go ahead in time to let syscheck perform a new scan
        time_travel = True

    print(f'+++ Diff: {get_configuration["elements"]}')
    regular_file_cud(folder=folder, log_monitor=wazuh_log_monitor, time_travel=time_travel, n_regular=1, min_timeout=3,
                     report_changes=True, no_diff=hidden_content, f_name=filename, content=content)
