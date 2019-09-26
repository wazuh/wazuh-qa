# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import glob
import os
import re
import time
from datetime import timedelta

import pytest
from wazuh_testing.fim import callback_detect_end_scan, callback_detect_event, LOG_FILE_PATH, FIFO, SOCKET, REGULAR, \
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
@pytest.mark.parametrize('name, filetype, content, checkers, applies_to_config', [
    ('file', REGULAR, 'Sample content', options, 'ossec.conf'),
    ('file2', REGULAR, b'Sample content', options, 'ossec.conf'),
    ('socketfile', SOCKET, '', options, 'ossec.conf'),
    ('file3', REGULAR, 'Sample content', options, 'ossec.conf'),
    ('fifofile', FIFO, '', options, 'ossec.conf'),
    ('file4', REGULAR, b'', options, 'ossec.conf')
])
def test_create_file_scheduled(folder, name, filetype, content, checkers, applies_to_config,
                               get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """ Checks if a special or regular file creation is detected by syscheck using scheduled monitoring"""

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    # Go ahead in time to let syscheck perform a new scan
    TimeMachine.travel_to_future(timedelta(hours=13))

    if filetype == REGULAR:
        # Wait until event is detected
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        validate_event(event, checkers)

        # Wait for FIM scan to finish
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_end_scan)
        time.sleep(3)
    else:
        with pytest.raises(TimeoutError):
            assert wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)


@pytest.mark.parametrize('applies_to_config', [
    'ossec_realtime.conf',
    'ossec_whodata.conf'
])
@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('name, filetype, content, checkers', [
    ('file', REGULAR, 'Sample content', options),
    ('file2', REGULAR, b'Sample content', options),
    ('socket_file', SOCKET, '', options),
    ('file3', REGULAR, '', options),
    ('fifo_file', FIFO, '', options),
    ('file4', REGULAR, b'', options),
])
def test_create_file_realtime_whodata(folder, name, filetype, content, checkers, applies_to_config,
                                      get_ossec_configuration, configure_environment, restart_wazuh,
                                      wait_for_initial_scan):
    """ Checks if a special or regular file creation is detected by syscheck using realtime and whodata monitoring"""
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    if filetype == REGULAR:
        # Wait until event is detected
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        validate_event(event, checkers)
    else:
        with pytest.raises(TimeoutError):
            assert wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
