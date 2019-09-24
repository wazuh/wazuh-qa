# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import glob
import os
import re
import time
from collections import Counter
from datetime import timedelta

import pytest
from jq import jq
from wazuh_testing.fim import callback_detect_end_scan, callback_detect_event, LOG_FILE_PATH, FIFO, SOCKET, REGULAR, \
    create_file, validate_event, CHECK_ALL
from wazuh_testing.tools import TimeMachine, FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.parametrize('folder, name, filetype, content, checkers, applies_to_config', [
    (testdir1, 'file', REGULAR, 'Sample content', options, 'ossec.conf'),
    (testdir1, 'file2', REGULAR, b'Sample content', options, 'ossec.conf'),
    (testdir1, 'socketfile', SOCKET, '', options, 'ossec.conf'),
    (testdir1, 'file3', REGULAR, '', options, 'ossec.conf'),
    (testdir1, 'fifofile', FIFO, '', options, 'ossec.conf'),
    (testdir1, 'file4', REGULAR, b'', options, 'ossec.conf'),
    (testdir2, 'file', REGULAR, 'Sample content', options, 'ossec.conf'),
    (testdir2, 'file2', REGULAR, b'Sample content', options, 'ossec.conf'),
    (testdir2, 'socketfile', SOCKET, '', options, 'ossec.conf'),
    (testdir2, 'file3', REGULAR, '', options, 'ossec.conf'),
    (testdir2, 'fifofile', FIFO, '', options, 'ossec.conf'),
    (testdir2, 'file4', REGULAR, b'', options, 'ossec.conf')
])
def test_create_file_scheduled(folder, name, filetype, content, checkers, applies_to_config,
                      get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """Checks if a special or regular file creation is detected by syscheck using scheduled monitoring"""

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    # Go ahead in time to let syscheck perform a new scan
    print("Muevo el reloj 13 horas al futuro")
    TimeMachine.travel_to_future(timedelta(hours=13))

    if filetype == REGULAR:
        # Wait until event is detected
        print("Espero a que salte el evento")
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        validate_event(event, options)

        # Wait for FIM scan to finish
        print("Espero a que termine el scan")
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_end_scan)
        print("Espero 3 segundos")
        time.sleep(3)
    else:
        with pytest.raises(TimeoutError):
            assert wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)


@pytest.mark.parametrize('folder, name, filetype, content, checkers, applies_to_config', [
    (testdir1, 'file', REGULAR, 'Sample content', options, 'ossec_realtime.conf'),
    (testdir1, 'file2', REGULAR, b'Sample content', options, 'ossec_realtime.conf'),
    (testdir1, 'socketfile', SOCKET, '', options, 'ossec_realtime.conf'),
    (testdir1, 'file3', REGULAR, '', options, 'ossec_realtime.conf'),
    (testdir1, 'fifofile', FIFO, '', options, 'ossec_realtime.conf'),
    (testdir1, 'file4', REGULAR, b'', options, 'ossec_realtime.conf'),
    (testdir2, 'file', REGULAR, 'Sample content', options, 'ossec_realtime.conf'),
    (testdir2, 'file2', REGULAR, b'Sample content', options, 'ossec_realtime.conf'),
    (testdir2, 'socketfile', SOCKET, '', options, 'ossec_realtime.conf'),
    (testdir2, 'file3', REGULAR, '', options, 'ossec_realtime.conf'),
    (testdir2, 'fifofile', FIFO, '', options, 'ossec_realtime.conf'),
    (testdir2, 'file4', REGULAR, b'', options, 'ossec_realtime.conf')
])
def test_create_file_realtime(folder, name, filetype, content, checkers, applies_to_config,
                               get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """Checks if a special or regular file creation is detected by syscheck using realtime monitoring"""
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    if filetype == REGULAR:
        # Wait until event is detected
        print("Espero a que salte el evento")
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        validate_event(event, options)
    else:
        with pytest.raises(TimeoutError):
            assert wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)


@pytest.mark.parametrize('folder, name, filetype, content, checkers, applies_to_config', [
    (testdir1, 'file', REGULAR, 'Sample content', options, 'ossec_whodata.conf'),
    (testdir1, 'file2', REGULAR, b'Sample content', options, 'ossec_whodata.conf'),
    (testdir1, 'socketfile', SOCKET, '', options, 'ossec_whodata.conf'),
    (testdir1, 'file3', REGULAR, '', options, 'ossec_whodata.conf'),
    (testdir1, 'fifofile', FIFO, '', options, 'ossec_whodata.conf'),
    (testdir1, 'file4', REGULAR, b'', options, 'ossec_whodata.conf'),
    (testdir2, 'file', REGULAR, 'Sample content', options, 'ossec_whodata.conf'),
    (testdir2, 'file2', REGULAR, b'Sample content', options, 'ossec_whodata.conf'),
    (testdir2, 'socketfile', SOCKET, '', options, 'ossec_whodata.conf'),
    (testdir2, 'file3', REGULAR, '', options, 'ossec_whodata.conf'),
    (testdir2, 'fifofile', FIFO, '', options, 'ossec_whodata.conf'),
    (testdir2, 'file4', REGULAR, b'', options, 'ossec_whodata.conf')
])
def test_create_file_whodata(folder, name, filetype, content, checkers, applies_to_config,
                               get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """Checks if a special or regular file creation is detected by syscheck using whodata monitoring"""
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create files
    create_file(filetype, name, folder, content)

    if filetype == REGULAR:
        # Wait until event is detected
        print("Espero a que salte el evento")
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        validate_event(event, options)
    else:
        with pytest.raises(TimeoutError):
            assert wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)


@pytest.mark.parametrize('folder, checkers, time_travel,  applies_to_config', [
    (testdir1, options, 'YES', 'ossec.conf'),
    (testdir1, options, 'NO', 'ossec_realtime.conf'),
    (testdir1, options, 'NO', 'ossec_whodata.conf')
])
def test_regular_file_changes(folder, checkers, time_travel, applies_to_config,
                       get_ossec_configuration, configure_environment, restart_wazuh, wait_for_initial_scan):
    """Checks if syscheckd detects regular file changes (add, modify, delete)"""
    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    n_regular = 3
    min_timeout = 5
    # Create text files
    for name in range(n_regular):
        create_file(REGULAR, f'regular_{name}', folder, '')

    # Check if scheduled for time traveling
    if time_travel == 'YES':
        TimeMachine.travel_to_future(timedelta(hours=13))

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=max(n_regular*0.01, min_timeout), callback=callback_detect_event,
                                     accum_results=n_regular).result()

    # Validate checkers for every event
    for ev in events:
        validate_event(ev, options)

    # Are the n_regular events of type 'added'?
    types = Counter(jq(".[].data.type").transform(events, multiple_output=True))
    assert(types['added'] == n_regular)

    # Are the n_regular events the files added?
    file_paths = jq(".[].data.path").transform(events, multiple_output=True)
    for name in range(n_regular):
        assert(os.path.join(folder, f'regular_{name}') in file_paths)

    # Modify previous text files
    for name in range(n_regular):
        create_file(REGULAR, f'regular_{name}', folder, '')

    # Check if scheduled for time traveling
    if time_travel == 'YES':
        TimeMachine.travel_to_future(timedelta(hours=13))

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=max(n_regular * 0.01, min_timeout), callback=callback_detect_event,
                                     accum_results=n_regular).result()

    # Validate checkers for every event
    for ev in events:
        validate_event(ev, options)

    # Are the n_regular events of type 'modified'?
    types = Counter(jq(".[].data.type").transform(events, multiple_output=True))
    assert (types['modified'] == n_regular)

    # Are the n_regular events the files modified?
    file_paths = jq(".[].data.path").transform(events, multiple_output=True)
    for name in range(n_regular):
        assert (os.path.join(folder, f'regular_{name}') in file_paths)

    # Delete previous text files
    for name in range(n_regular):
        os.remove(os.path.join(folder, f'regular_{name}'))

    # Check if scheduled for time traveling
    if time_travel == 'YES':
        TimeMachine.travel_to_future(timedelta(hours=13))

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=max(n_regular * 0.01, min_timeout), callback=callback_detect_event,
                                     accum_results=n_regular).result()

    # Are the n_regular events of type 'deleted'?
    types = Counter(jq(".[].data.type").transform(events, multiple_output=True))
    assert (types['deleted'] == n_regular)

    # Are the n_regular events the files modified?
    file_paths = jq(".[].data.path").transform(events, multiple_output=True)
    for name in range(n_regular):
        assert (os.path.join(folder, f'regular_{name}') in file_paths)