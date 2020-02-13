# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, SYMLINK, HARDLINK, \
    callback_entries_path_count, check_time_travel
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir1', 'subdir')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2, testdir1_subdir = test_directories

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m, )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def extra_configuration_before_yield():
    create_file(REGULAR, testdir1, 'test_1', content='')
    create_file(REGULAR, testdir1, 'test_2', content='')
    create_file(SYMLINK, testdir1, 'symlink', target=os.path.join(testdir1, 'test_1'))
    create_file(HARDLINK, testdir1, 'hardlink', target=os.path.join(testdir1, 'test_2'))


def test_entries_match_path_count(get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Check if FIM entries match the path count

    It creates two regular files, a symlink and a hard link before the scan begins. After events are logged,
    we should have 3 inode entries and a path count of 4.
    """
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    entries, path_count = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_entries_path_count,
                                                  error_message='[ERROR] Did not receive expected '
                                                                '"Fim inode entries: ..., path count: ..." event'
                                                  ).result()
    check_time_travel(True)

    if entries and path_count:
        assert entries == '3' and path_count == '4', 'Wrong number of inodes and path count'
    else:
        raise AssertionError('Wrong number of inodes and path count')
