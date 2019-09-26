# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time
from datetime import timedelta

import pytest

from wazuh_testing.fim import (CHECK_ALL, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_end_scan, callback_detect_event,
                               create_file, validate_event)
from wazuh_testing.tools import (FileMonitor, TimeMachine, check_apply_test,
                                 load_wazuh_configurations)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories
options = {CHECK_ALL}


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder, name, filetype, content, tags_to_apply', [
    (testdir1, 'file', REGULAR, 'Sample content', {'no_realtime'}),
    (testdir1, 'file', REGULAR, b'Sample content', {'no_realtime'}),
    (testdir1, 'file', REGULAR, '', {'no_realtime'}),
    (testdir1, 'file', REGULAR, b'', {'no_realtime'}),
    (testdir2, 'file', REGULAR, 'Sample content', {'no_realtime'}),
    (testdir2, 'file', REGULAR, b'Sample content', {'no_realtime'}),
    (testdir2, 'file', REGULAR, '', {'no_realtime'}),
    (testdir2, 'file', REGULAR, b'', {'no_realtime'})
])
def test_regular_file(folder, name, filetype, content, tags_to_apply,
                      get_configuration, configure_environment, restart_wazuh,
                      wait_for_initial_scan):
    """Check if a special file creation is detected by syscheck."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

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


@pytest.mark.parametrize('folder, name, filetype, content, checkers, tags_to_apply', [
    (testdir1, 'file', REGULAR, 'Sample content', options, {'realtime'}),
    (testdir1, 'file', REGULAR, b'Sample content', options, {'realtime'}),
    (testdir1, 'file', REGULAR, '', options, {'realtime'}),
    (testdir1, 'file', REGULAR, b'', options, {'realtime'}),
    (testdir2, 'file', REGULAR, 'Sample content', options, {'realtime'}),
    (testdir2, 'file', REGULAR, '', options, {'realtime'}),
    (testdir2, 'file', REGULAR, b'', options, {'realtime'})
])
def test_regular_file_realtime(folder, name, filetype, content, checkers,
                               tags_to_apply, get_configuration,
                               configure_environment, restart_wazuh):
    """Check if a regular file creation is detected by syscheck."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    print("Espero a que salte el evento")
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    validate_event(event, checks=options)


@pytest.mark.parametrize('folder, name, filetype, content, tags_to_apply', [
    (testdir1, 'file', FIFO, '', {'no_realtime'}),
    (testdir2, 'file', FIFO, '', {'no_realtime'}),
    (testdir1, 'file', SOCKET, '', {'no_realtime'}),
    (testdir2, 'file', SOCKET, '', {'no_realtime'})
])
def _test_special_file_realtime(folder, name, filetype, content,
                                tags_to_apply, get_configuration,
                                configure_environment, restart_wazuh):
    """Check if a regular file creation is detected by syscheck."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files
    create_file(filetype, folder, content)

    # Wait until event is detected
    print("Espero a que salte el evento")
    with pytest.raises(TimeoutError):
        assert wazuh_log_monitor.start(timeout=10,
                                       callback=callback_detect_event)
