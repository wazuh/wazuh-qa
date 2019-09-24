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
from wazuh_testing.tools import FileMonitor, truncate_file

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [
                    os.path.join('/', 'testdir_reports'),
                    os.path.join('/', 'testdir_nodiff')
                    ]
testdir_reports, testdir_nodiff = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


create_files = [
    ('file1', REGULAR, 'Sample content'),
    #('file2', REGULAR, ''),
    ('file3', REGULAR, b'Sample content')
    #('file4', REGULAR, b'')
]


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.parametrize('name, filetype, content', create_files)
@pytest.mark.parametrize('folder, checkers', [
    # <directories whodata="yes" report_changes="yes">/testdir_reports</directories>
    (testdir_reports, REQUIRED_ATTRIBUTES[CHECK_ALL])
])
def test_reports_file(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
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

    # Check if the diff file is created
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', folder[1:], name, 'last-entry.gz')
    print(f'diff file path: {diff_file}')
    assert (os.path.isfile(diff_file) == True)

    # Delete file
    regular_path = os.path.join(folder, name)
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)


@pytest.mark.parametrize('name, filetype, content', create_files)
@pytest.mark.parametrize('folder, checkers', [
    # <directories whodata="yes" report_changes="yes">/testdir_nodiff</directories>
    (testdir_nodiff, REQUIRED_ATTRIBUTES[CHECK_ALL])
])
def _test_nodiff(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
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


@pytest.mark.parametrize('name, filetype, content', [('file', REGULAR, 'Sample content')])
@pytest.mark.parametrize('folder, checkers', [
    # <directories whodata="yes" report_changes="yes">/testdir_delete</directories>
    (testdir_nodiff, REQUIRED_ATTRIBUTES[CHECK_ALL])
])
def test_delete_diff_creation(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
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


@pytest.fixture(scope='function', params=glob.glob(os.path.join(test_data_path, 'ossec_delete.conf')))
def get_ossec_configuration_report(request):
    return request.param

@pytest.fixture(scope='function')
def configure_environment_report(get_ossec_configuration_report, request):
    # Place configuration in path
    shutil.copy(get_ossec_configuration_report, WAZUH_CONF_PATH)
    shutil.chown(WAZUH_CONF_PATH, 'root', 'ossec')
    os.chmod(WAZUH_CONF_PATH, mode=0o660)

    yield
    # Remove created folders
    for test_dir in test_directories:
        shutil.rmtree(test_dir, ignore_errors=True)

@pytest.fixture(scope='function')
def wait_for_initial_scan_report(get_ossec_configuration_report, request):
    # Wait for initial FIM scan to end
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    file_monitor.start(timeout=60, callback=callback_detect_end_scan)

    # Add additional sleep to avoid changing system clock issues (TO BE REMOVED when syscheck has not sleeps anymore)
    time.sleep(11)

@pytest.fixture(scope='function')
def restart_wazuh_report(get_ossec_configuration_report, request):
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Restart Wazuh and wait for the command to end
    p = subprocess.Popen(["service", "wazuh-manager", "restart"])
    p.wait()

@pytest.mark.parametrize('folder, name, filetype, content', [(testdir_nodiff, 'file', REGULAR, 'Sample content')])
def test_delete_diff_deletion(folder, name, filetype, content, configure_environment_report, restart_wazuh_report, wait_for_initial_scan_report):
    # Check if the diff file is deleted
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', folder[1:], name, 'last-entry.gz')
    print(f'diff file path: {diff_file}')
    assert (os.path.isfile(diff_file) == False)
