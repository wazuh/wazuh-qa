# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import glob
import pytest
import time
import subprocess
import shutil

from wazuh_testing.fim import *
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, truncate_file)


# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [
                    os.path.join('/', 'testdir_reports'),
                    os.path.join('/', 'testdir_nodiff')
                    ]
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}


wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'schedule_report'},
    {'realtime_report'},
    {'whodata_report'}
])
@pytest.mark.parametrize('folder, checkers, no_diff', [
    (testdir_reports, options, False),
    (testdir_nodiff, options, True)
])
def test_reports_file_and_nodiff(folder, checkers, no_diff, tags_to_apply,
                    get_configuration, configure_environment,
                      restart_wazuh, wait_for_initial_scan):

    check_apply_test(tags_to_apply, get_configuration['tags'])
    n_regular_files = 1
    min_timeout = 3
    time_travel = False
    if tags_to_apply == {'schedule'}:
        print("timetravel true")
        time_travel = True
    regular_file_cud(folder, time_travel, n_regular_files, min_timeout, wazuh_log_monitor, options=checkers,
                     content_changes=True, no_diff=no_diff)
