# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import glob
import pytest
import time

from wazuh_testing.fim import *
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [
                    os.path.join('/', 'testdir_reports'),
                    os.path.join('/', 'testdir_nodiff')
                    ]
testdir_reports, testdir_nodiff = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec.conf')))
def get_ossec_configuration(request):
    return request.param

@pytest.mark.parametrize('name, filetype, content', [
    ('file1', REGULAR, 'Sample content'),
    #('file2', REGULAR, ''),
    ('file3', REGULAR, b'Sample content')
    #('file4', REGULAR, b'')
])
@pytest.mark.parametrize('folder, checkers', [
    # <directories whodata="yes" report_changes="yes">/testdir_reports</directories>
    (testdir_reports, REQUIRED_ATTRIBUTES[CHECK_ALL])
])
def test_fim_reports(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
    # Create file
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)

    # Modify file
    regular_path = os.path.join(folder, name)
    modify_file(folder, name, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
    assert (event['data'].get('content_changes') is not None)

    # Delete file
    regular_path = os.path.join(folder, name)
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)


@pytest.mark.parametrize('name, filetype, content', [
    ('file1', REGULAR, 'Sample content'),
    #('file2', REGULAR, ''),
    ('file3', REGULAR, b'Sample content')
    #('file4', REGULAR, b'')
])
@pytest.mark.parametrize('folder, checkers', [
    # <directories whodata="yes" report_changes="yes">/testdir_nodiff</directories>
    (testdir_nodiff, REQUIRED_ATTRIBUTES[CHECK_ALL])
])
def test_fim_nodiff(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
    # Create file
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)

    # Modify file
    regular_path = os.path.join(folder, name)
    modify_file(folder, name, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
    assert ('<Diff truncated because nodiff option>' in event['data'].get('content_changes'))

    # Delete file
    regular_path = os.path.join(folder, name)
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
