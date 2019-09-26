# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import glob
import os
import re
import time
from datetime import timedelta

import pytest
from wazuh_testing.fim import callback_detect_end_scan, callback_detect_event, LOG_FILE_PATH, \
    create_file, validate_event, CHECK_ALL, regular_file_cud
from wazuh_testing.tools import TimeMachine, FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('checkers, is_scheduled,  applies_to_config', [
    (options, True, 'ossec.conf'),
    (options, False, 'ossec_realtime.conf'),
    (options, False, 'ossec_whodata.conf')
])
def test_regular_file_changes(folder, checkers, is_scheduled, applies_to_config,
                              get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """ Checks if syscheckd detects regular file changes (add, modify, delete)"""
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    n_regular = 3
    min_timeout = 3

    regular_file_cud(folder, is_scheduled, n_regular, min_timeout, wazuh_log_monitor, checkers)
