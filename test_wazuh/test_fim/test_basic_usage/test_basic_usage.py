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
    create_file, validate_event, CHECK_ALL
from wazuh_testing.tools import TimeMachine, FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.parametrize('folder, name, filetype, content, applies_to_config', [
    (testdir1, 'file', REGULAR, 'Sample content', 'ossec.conf'),
    (testdir1, 'file', REGULAR, b'Sample content', 'ossec.conf'),
    (testdir1, 'file', REGULAR, '', 'ossec.conf'),
    (testdir1, 'file', REGULAR, b'', 'ossec.conf'),
    (testdir2, 'file', REGULAR, 'Sample content', 'ossec.conf'),
    (testdir2, 'file', REGULAR, b'Sample content', 'ossec.conf'),
    (testdir2, 'file', REGULAR, '', 'ossec.conf'),
    (testdir2, 'file', REGULAR, b'', 'ossec.conf')
])
def test_regular_file(folder, name, filetype, content, applies_to_config,
                      get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """Checks if a special file creation is detected by syscheck"""

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    # Go ahead in time to let syscheck perform a new scan
    print("Muevo el reloj 13 horas al futuro")
    TimeMachine.travel_to_future(timedelta(hours=13))

    # Wait until event is detected
    print("Espero a que salte el evento")
    wazuh_log_monitor.start(timeout=10, callback=callback_detect_event)

    # Wait for FIM scan to finish
    print("Espero a que termine el scan")
    wazuh_log_monitor.start(timeout=10, callback=callback_detect_end_scan)
    print("Espero 11 segundos")
    time.sleep(11)


@pytest.mark.parametrize('folder, name, filetype, content, checkers, applies_to_config', [
    (testdir1, 'file', REGULAR, 'Sample content', options, 'ossec_realtime.*conf'),
    (testdir1, 'file', REGULAR, b'Sample content', options, 'ossec_realtime.*conf'),
    (testdir1, 'file', REGULAR, '', options, 'ossec_realtime.*conf'),
    (testdir1, 'file', REGULAR, b'', options, 'ossec_realtime.*conf'),
    (testdir2, 'file', REGULAR, 'Sample content', options, 'ossec_realtime.*conf'),
    (testdir2, 'file', REGULAR, b'Sample content', options, 'ossec_realtime.*conf'),
    (testdir2, 'file', REGULAR, '', options, 'ossec_realtime.*conf'),
    (testdir2, 'file', REGULAR, b'', options, 'ossec_realtime.*conf')
])
def test_regular_file_realtime(folder, name, filetype, content, checkers, applies_to_config,
                               get_ossec_configuration, configure_environment, restart_wazuh):
    """Checks if a regular file creation is detected by syscheck"""
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    print("Espero a que salte el evento")
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    validate_event(event, checks=options)


@pytest.mark.parametrize('folder, name, filetype, content', [
    (testdir1, 'file', FIFO, ''),
    (testdir2, 'file', FIFO, ''),
    (testdir1, 'file', SOCKET, ''),
    (testdir2, 'file', SOCKET, '')
])
def _test_special_file_realtime(folder, name, filetype, content, configure_environment, restart_wazuh):
    """Checks if a regular file creation is detected by syscheck"""
    # Create files
    create_file(filetype, folder, content)

    # Wait until event is detected
    print("Espero a que salte el evento")
    with pytest.raises(TimeoutError):
        assert wazuh_log_monitor.start(timeout=10, callback=callback_detect_event)
