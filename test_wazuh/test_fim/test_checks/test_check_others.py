# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing.fim import (CHECK_ALL, CHECK_ATTRS, CHECK_GROUP, CHECK_INODE, CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE, CHECK_SUM,
                               LOG_FILE_PATH, REQUIRED_ATTRIBUTES, regular_file_cud)
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations


# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

if sys.platform == 'win32':
    test_directories = [os.path.join('C:', os.sep, 'testdir1'), os.path.join('C:', os.sep, 'testdir2')]
    test_directories = [os.path.join('C:', os.sep, 'testdir1'), os.path.join('C:', os.sep, 'testdir2'),
                        os.path.join('C:', os.sep, 'testdir3'), os.path.join('C:', os.sep, 'testdir4'),
                        os.path.join('C:', os.sep, 'testdir5'), os.path.join('C:', os.sep, 'testdir6'),
                        os.path.join('C:', os.sep, 'testdir7'), os.path.join('C:', os.sep, 'testdir8'),
                        os.path.join('C:', os.sep, 'testdir9'), os.path.join('C:', os.sep, 'testdir0')]
    configurations_path = os.path.join(test_data_path, 'wazuh_check_others_windows.yaml')

else:
    test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'),
                        os.path.join('/', 'testdir3'), os.path.join('/', 'testdir4'),
                        os.path.join('/', 'testdir5'), os.path.join('/', 'testdir6'),
                        os.path.join('/', 'testdir7'), os.path.join('/', 'testdir8'),
                        os.path.join('/', 'testdir9'), os.path.join('/', 'testdir0')]
    configurations_path = os.path.join(test_data_path, 'wazuh_check_others.yaml')

testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories


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

if sys.platform == 'win32':
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM]),
                        (testdir2, {CHECK_MD5SUM}),
                        (testdir3, {CHECK_SHA1SUM}),
                        (testdir4, {CHECK_SHA256SUM}),
                        (testdir5, {CHECK_SIZE}),
                        (testdir6, {CHECK_OWNER}),
                        (testdir7, {CHECK_ATTRS}),
                        (testdir8, {CHECK_PERM}),
                        (testdir9, {CHECK_MTIME})
                        ]
else:
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM]),
                        (testdir2, {CHECK_MD5SUM}),
                        (testdir3, {CHECK_SHA1SUM}),
                        (testdir4, {CHECK_SHA256SUM}),
                        (testdir5, {CHECK_SIZE}),
                        (testdir6, {CHECK_OWNER}),
                        (testdir7, {CHECK_GROUP}),
                        (testdir8, {CHECK_PERM}),
                        (testdir9, {CHECK_MTIME}),
                        (testdir0, {CHECK_INODE})
                        ]


@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_others_individually(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_initial_scan):
    """Test the behaviour of every Check option individually without using the Check_all option. Check_all option will
    be set to "no" in order to avoid using the default check_all configuration.

    Example:
        check_all="no" check_sum="yes"
        check_all="no" check_mtime="yes"
        ...

    This test is intended to be used with valid configurations files. Each execution of this test will configure the
    environment properly, restart the service and wait for the initial scan.

    :param path string Directory where the file is being created and monitored
    :param checkers dict Dict with all the check options to be used
    """
    check_apply_test({'test_check_others_individually'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


if sys.platform == 'win32':
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM] | {CHECK_SIZE}),
                        (testdir2, {CHECK_MD5SUM} | {CHECK_OWNER} | {CHECK_MTIME}),
                        (testdir3, {CHECK_SHA1SUM} | {CHECK_SHA256SUM}),
                        (testdir4, {CHECK_SIZE} | {CHECK_PERM} | {CHECK_ATTRS}),
                        (testdir5, {CHECK_OWNER} | {CHECK_ATTRS}),
                        (testdir6, {CHECK_PERM} | {CHECK_MTIME}),
                        (testdir7, {CHECK_ATTRS} | {CHECK_MTIME}),
                        (testdir8, {CHECK_SHA256SUM})
                        ]
else:
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM] | {CHECK_SIZE}),
                        (testdir2, {CHECK_MD5SUM} | {CHECK_GROUP} | {CHECK_MTIME}),
                        (testdir3, {CHECK_SHA1SUM} | {CHECK_SHA256SUM}),
                        (testdir4, {CHECK_SIZE} | {CHECK_PERM} | {CHECK_INODE}),
                        (testdir5, {CHECK_OWNER} | {CHECK_GROUP}),
                        (testdir6, {CHECK_PERM} | {CHECK_MTIME}),
                        (testdir7, {CHECK_GROUP} | {CHECK_MTIME}),
                        (testdir8, {CHECK_SHA256SUM})
                        ]


@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_others(path, checkers, get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Test the behaviour of several combinations of Check options over the same directory with Check_all disabled to
    avoid using the default check_all configuration. The order of the checks (including check_all="no") will be
    different on each case to test the behaviour of check_all="no".

    Example:
        check_all: "no" check_size: "yes" check_sum: "yes"
        check_all: "no" check_md5sum: "yes" check_mtime: "yes" check_group: "yes"
        check_md5sum: "yes" check_all: "no" check_mtime: "yes" check_group: "yes"
        ...

    This test is intended to be used with valid configurations files. Each execution of this test will configure the
    environment properly, restart the service and wait for the initial scan.

    :param path string Directory where the file is being created and monitored
    :param checkers dict Dict with all the check options to be used
    """
    check_apply_test({'test_check_others'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
