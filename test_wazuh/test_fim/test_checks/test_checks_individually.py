# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.fim import (CHECK_ALL, CHECK_GROUP, CHECK_INODE,
                               CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM,
                               CHECK_SIZE, CHECK_SUM, LOG_FILE_PATH, REGULAR,
                               REQUIRED_ATTRIBUTES, callback_detect_event,
                               regular_file_cud,create_file, modify_file, delete_file, validate_event)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_individually_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), 
                    os.path.join('/', 'testdir3'), os.path.join('/', 'testdir4'), 
                    os.path.join('/', 'testdir5'), os.path.join('/', 'testdir6'), 
                    os.path.join('/', 'testdir7'), os.path.join('/', 'testdir8'), 
                    os.path.join('/', 'testdir9'), os.path.join('/', 'testdir0')]
testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

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
"""
@pytest.mark.parametrize('path, checkers', [
    (testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM]),
    (testdir2, REQUIRED_ATTRIBUTES[CHECK_MD5SUM]),
    (testdir3, REQUIRED_ATTRIBUTES[CHECK_SHA1SUM]),
    (testdir4, REQUIRED_ATTRIBUTES[CHECK_SHA256SUM]),
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_SIZE]),
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_OWNER]),
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_GROUP]),
    (testdir8, REQUIRED_ATTRIBUTES[CHECK_PERM]),
    (testdir9, REQUIRED_ATTRIBUTES[CHECK_MTIME]),
    (testdir0, REQUIRED_ATTRIBUTES[CHECK_INODE])
])
"""
@pytest.mark.parametrize('path, checkers', [
    (testdir1, {CHECK_SUM}),
    (testdir2, {CHECK_MD5SUM}),
    (testdir3, {CHECK_SHA1SUM}),
    (testdir4, {CHECK_SHA256SUM}),
    (testdir5, {CHECK_SIZE}),
    (testdir6, {CHECK_OWNER}),
    (testdir7, {CHECK_GROUP}),
    (testdir8, {CHECK_PERM}),
    (testdir9, {CHECK_MTIME}),
    (testdir0, {CHECK_INODE})
])
def test_checks_individually(path, checkers, get_configuration, configure_environment, 
                             restart_wazuh, wait_for_initial_scan):
    #check_apply_test({'realtime'}, get_configuration['tags'])

    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        regular_file_cud(path, wazuh_log_monitor, min_timeout=2, options=checkers, time_travel = True)
    else:
        regular_file_cud(path, wazuh_log_monitor, min_timeout=2, options=checkers)
