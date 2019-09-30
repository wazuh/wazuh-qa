# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import pytest
import re
import shutil
import stat

from datetime import timedelta
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, validate_event, CHECK_ALL, regular_file_cud
from wazuh_testing.tools import FileMonitor, TimeMachine


def get_full_path(basename, subdirname, num_subdirectories):
    """Create a hierarchy of folders on `basename` with as many subdirectories recursively as specified.
        Example:
            get_full_path("/testdir1", "subdir", 3)

        Result:
            /testdir1/subdir1/subdir2/subdir3/

        :param basename string The root path of the hierarchy.
        :param subdirname string The name of the subdirectory. It will be appended with a number.
        :param num_subdirectories int The number of subdirectories to create recursively
    """
    path = basename
    for n in range(1, num_subdirectories + 1):
        path = os.path.join(path, subdirname + str(n))
    return path


subdir = "subdir"
subdir_space = "sub dir "

dir_no_recursion = "/test_no_recursion"
dir_no_recursion_space = "/test no recursion"
dir_recursion_1 = "/test_recursion_1"
dir_recursion_1_space = "/test recursion 1"
dir_recursion_5 = "/test_recursion_5"
dir_recursion_5_space = "/test recursion 5"
dir_recursion_320 = "/test_recursion_320"
dir_recursion_320_space = "/test recursion 320"

test_data_path = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [
    dir_no_recursion,
    dir_recursion_1,
    dir_recursion_5,
    dir_recursion_320,
    dir_no_recursion_space,
    dir_recursion_1_space,
    dir_recursion_5_space,
    dir_recursion_320_space
]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


def create_file(path, filename, mode, content):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, filename), mode) as f:
        f.write(content)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'wazuh*.conf')))
def get_ossec_configuration(request):
    return request.param


general_parametrize_list = [
    (False, "/dummytest"),
    (False, "/dummytest"),

    (True,  get_full_path(dir_no_recursion, subdir, 0)),
    (False, get_full_path(dir_no_recursion, subdir, 1)),

    (True,  get_full_path(dir_no_recursion_space, subdir_space, 0)),
    (False, get_full_path(dir_no_recursion_space, subdir_space, 1)),

    (True,  get_full_path(dir_recursion_1, subdir, 0)),
    (True,  get_full_path(dir_recursion_1, subdir, 1)),
    (False, get_full_path(dir_recursion_1, subdir, 5)),

    (True,  get_full_path(dir_recursion_1_space, subdir_space, 0)),
    (True,  get_full_path(dir_recursion_1_space, subdir_space, 1)),
    (False, get_full_path(dir_recursion_1_space, subdir_space, 5)),

    (True,  get_full_path(dir_recursion_5, subdir, 0)),
    (True,  get_full_path(dir_recursion_5, subdir, 5)),
    (False, get_full_path(dir_recursion_5, subdir, 10)),

    (True,  get_full_path(dir_recursion_5_space, subdir_space, 0)),
    (True,  get_full_path(dir_recursion_5_space, subdir_space, 5)),
    (False, get_full_path(dir_recursion_5_space, subdir_space, 10)),

    (True,  get_full_path(dir_recursion_320, subdir, 0)),
    (True,  get_full_path(dir_recursion_320, subdir, 5)),
    (True,  get_full_path(dir_recursion_320, subdir, 318)),

    (True,  get_full_path(dir_recursion_320_space, subdir_space, 0)),
    (True,  get_full_path(dir_recursion_320_space, subdir_space, 5)),
    (True,  get_full_path(dir_recursion_320_space, subdir_space, 318))
]
file_parametrize_list = [
    ('testfile', 'w', "Sample content"),
    ('b test file', 'wb', b"Sample content")
]


@pytest.mark.parametrize('should_be_triggered, path', general_parametrize_list)
@pytest.mark.parametrize('filename, mode, content', file_parametrize_list)
def test_recursion_realtime(should_be_triggered, path, filename, mode, content, get_ossec_configuration, configure_environment, restart_wazuh):
    """Main test for realtime recursion level
    """
    applies_to_config = "wazuh_recursion_realtime.conf"
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    n_regular = 2
    min_timeout = 3
    regular_file_cud(path, False, n_regular, min_timeout,
                     wazuh_log_monitor, should_be_triggered=should_be_triggered)


@pytest.mark.parametrize('should_be_triggered, path', general_parametrize_list)
@pytest.mark.parametrize('filename, mode, content', file_parametrize_list)
def test_recursion_scheduled(should_be_triggered, path, filename, mode, content, get_ossec_configuration, configure_environment, restart_wazuh):
    applies_to_config = "wazuh_recursion_scheduled.conf"
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    n_regular = 2
    min_timeout = 3
    regular_file_cud(path, True, n_regular, min_timeout,
                     wazuh_log_monitor, should_be_triggered=should_be_triggered)


@pytest.mark.parametrize('should_be_triggered, path', general_parametrize_list)
@pytest.mark.parametrize('filename, mode, content', file_parametrize_list)
def test_recursion_whodata(should_be_triggered, path, filename, mode, content, get_ossec_configuration, configure_environment, restart_wazuh):
    """Checks if files are correctly detected by syscheck with recursion level using whodata monitoring.

    This test is intended to be used with valid ignore configurations. It applies RegEx to match the name
     of the configuration file where the test applies. If the configuration file does not match the test 
     is skipped
    """
    applies_to_config = "wazuh_recursion_whodata.conf"

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    n_regular = 2
    min_timeout = 5
    regular_file_cud(path, False, n_regular, min_timeout,
                     wazuh_log_monitor, should_be_triggered=should_be_triggered)
