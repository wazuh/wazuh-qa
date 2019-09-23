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

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3'),
                    os.path.join('/', 'testdir4'), os.path.join('/', 'testdir5'), os.path.join('/', 'testdir6'),
                    os.path.join('/', 'testdir7'), os.path.join('/', 'testdir8'), os.path.join('/', 'testdir9'),
                    os.path.join('/', 'testdir0'),
                    os.path.join('/', 'testdir_tags'),
                    os.path.join('/', 'testdir_report_changes')
                    ]
testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0, testdir_tags, testdir_report_changes = test_directories

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
    # <directories whodata="yes" check_all="yes" check_sum="no">/testdir1</directories>
    (testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM]),
    # <directories whodata="yes" check_all="yes" check_md5sum="no">/testdir2</directories>
    (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM}),
    # <directories whodata="yes" check_all="yes" check_sha1sum="no">/testdir3</directories>
    (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA1SUM}),
    # <directories whodata="yes" check_all="yes" check_sha256sum="no">/testdir4</directories>
    (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM}),
    # <directories whodata="yes" check_all="yes" check_size="no">/testdir5</directories>
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SIZE}),
    # <directories whodata="yes" check_all="yes" check_owner="no">/testdir6</directories>
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_OWNER}),
    # <directories whodata="yes" check_all="yes" check_group="no">/testdir7</directories>
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_GROUP}),
    # <directories whodata="yes" check_all="yes" check_perm="no">/testdir8</directories>
    (testdir8, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM}),
    # <directories whodata="yes" check_all="yes" check_mtime="no">/testdir9</directories>
    (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MTIME}),
    # <directories whodata="yes" check_all="yes" check_inode="no">/testdir0</directories>
    (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE})
])
def test_fim_checks(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
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
    # <directories whodata="yes" report_changes="yes">/testdir_report_changes</directories>
    (testdir_report_changes, REQUIRED_ATTRIBUTES[CHECK_ALL])
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
    # <directories whodata="yes" tags="tag0,tag1,tag2,tag3,tag4,tag5,tag6,tag7,tag8,tag9">/testdir_tags</directories>
    (testdir_tags, REQUIRED_ATTRIBUTES[CHECK_ALL])
])
def test_fim_tags(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):
    defined_tags = 'tag0,tag1,tag2,tag3,tag4,tag5,tag6,tag7,tag8,tag9'
    # Create file
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
    assert (defined_tags == event['data']['tags'])

    # Modify file
    regular_path = os.path.join(folder, name)
    modify_file(folder, name, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
    assert (defined_tags == event['data']['tags'])

    # Delete file
    regular_path = os.path.join(folder, name)
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
    assert (defined_tags == event['data']['tags'])
