# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing.fim import (CHECK_ATTRS, CHECK_GROUP, CHECK_INODE, CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE, CHECK_SUM,
                               LOG_FILE_PATH, REQUIRED_ATTRIBUTES, regular_file_cud, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'), os.path.join(PREFIX, 'testdir4'),
                    os.path.join(PREFIX, 'testdir5'), os.path.join(PREFIX, 'testdir6'),
                    os.path.join(PREFIX, 'testdir7'), os.path.join(PREFIX, 'testdir8'),
                    os.path.join(PREFIX, 'testdir9'), os.path.join(PREFIX, 'testdir0')]
configurations_path = os.path.join(
    test_data_path, 'wazuh_check_others_windows.yaml' if sys.platform == 'win32' else 'wazuh_check_others.yaml')

testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

# configurations

p, m = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM]),
                    (testdir2, {CHECK_MD5SUM}),
                    (testdir3, {CHECK_SHA1SUM}),
                    (testdir4, {CHECK_SHA256SUM}),
                    (testdir5, {CHECK_SIZE}),
                    (testdir6, {CHECK_OWNER}),
                    (testdir8, {CHECK_PERM})]
if sys.platform == 'win32':
    parametrize_list.extend([
        (testdir7, {CHECK_ATTRS}),
        (testdir9, {CHECK_MTIME})
    ])
else:
    parametrize_list.extend([
        (testdir7, {CHECK_GROUP}),
        (testdir9, {CHECK_MTIME}),
        (testdir0, {CHECK_INODE})
    ])


@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_others_individually(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_fim_start):
    """
    Test the behavior of every Check option individually without using the Check_all option. Check_all option will
    be set to "no" in order to avoid using the default check_all configuration.

    Example:
        check_all="no" check_sum="yes"
        check_all="no" check_mtime="yes"
        ...

    Parameters
    ----------
    path : str
        Directory where the file is being created and monitored.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_check_others_individually'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM] | {CHECK_SIZE}),
                    (testdir3, {CHECK_SHA1SUM} | {CHECK_SHA256SUM}),
                    (testdir6, {CHECK_PERM} | {CHECK_MTIME}),
                    (testdir8, {CHECK_SHA256SUM})]

if sys.platform == 'win32':
    parametrize_list.extend([
        (testdir2, {CHECK_MD5SUM} | {CHECK_OWNER} | {CHECK_MTIME}),
        (testdir4, {CHECK_SIZE} | {CHECK_PERM} | {CHECK_ATTRS}),
        (testdir5, {CHECK_OWNER} | {CHECK_ATTRS}),
        (testdir7, {CHECK_ATTRS} | {CHECK_MTIME})
    ])
else:
    parametrize_list.extend([
        (testdir2, {CHECK_MD5SUM} | {CHECK_GROUP} | {CHECK_MTIME}),
        (testdir4, {CHECK_SIZE} | {CHECK_PERM} | {CHECK_INODE}),
        (testdir5, {CHECK_OWNER} | {CHECK_GROUP}),
        (testdir7, {CHECK_GROUP} | {CHECK_MTIME})
    ])


@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_others(path, checkers, get_configuration, configure_environment,
                      restart_syscheckd, wait_for_fim_start):
    """
    Test the behavior of several combinations of Check options over the same directory with Check_all disabled to
    avoid using the default check_all configuration. The order of the checks (including check_all="no") will be
    different on each case to test the behavior of check_all="no".

    Example:
        check_all: "no" check_size: "yes" check_sum: "yes"
        check_all: "no" check_md5sum: "yes" check_mtime: "yes" check_group: "yes"
        check_md5sum: "yes" check_all: "no" check_mtime: "yes" check_group: "yes"
        ...

    Parameters
    ----------
    path : str
        Directory where the file is being created and monitored.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_check_others'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
