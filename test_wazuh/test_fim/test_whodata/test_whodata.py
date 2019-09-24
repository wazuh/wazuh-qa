# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (CHECK_ALL, CHECK_GROUP, CHECK_INODE,
                               CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM,
                               CHECK_SIZE, CHECK_SUM, LOG_FILE_PATH, REGULAR,
                               REQUIRED_ATTRIBUTES, callback_detect_event,
                               create_file, delete_file, modify_file,
                               validate_event)
from wazuh_testing.tools import FileMonitor, check_apply_test, load_yaml


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
section_configuration_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3'),
                    os.path.join('/', 'testdir4'), os.path.join('/', 'testdir5'), os.path.join('/', 'testdir6'),
                    os.path.join('/', 'testdir7'), os.path.join('/', 'testdir8'), os.path.join('/', 'testdir9'),
                    os.path.join('/', 'testdir0'),
                    os.path.join('/', 'testdir_tags'),
                    os.path.join('/', 'testdir_report_changes')
                    ]
testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0, testdir_tags, testdir_report_changes = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_yaml(section_configuration_path)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('name, filetype, content', [
    ('file1', REGULAR, 'Sample content'),
    #('file2', REGULAR, ''),
    ('file3', REGULAR, b'Sample content')
    #('file4', REGULAR, b'')
])
@pytest.mark.parametrize('folder, checkers, ids_to_apply', [
    (testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM], {'all'}),
    # <directories whodata="yes" check_all="yes" check_md5sum="no">/testdir2</directories>
    (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_sha1sum="no">/testdir3</directories>
    (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA1SUM}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_sha256sum="no">/testdir4</directories>
    (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_size="no">/testdir5</directories>
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SIZE}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_owner="no">/testdir6</directories>
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_OWNER}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_group="no">/testdir7</directories>
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_GROUP}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_perm="no">/testdir8</directories>
    (testdir8, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_mtime="no">/testdir9</directories>
    (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MTIME}, {'all'}),
    # <directories whodata="yes" check_all="yes" check_inode="no">/testdir0</directories>
    (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE}, {'all'})
])
def test_fim_checks(folder, name, filetype, content, checkers,
                    ids_to_apply, get_configuration,
                    configure_environment, restart_wazuh,
                    wait_for_initial_scan):
    check_apply_test(ids_to_apply, get_configuration['identifiers'])

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
@pytest.mark.parametrize('folder, checkers, ids_to_apply', [
    # <directories whodata="yes" report_changes="yes">/testdir_report_changes</directories>
    (testdir_report_changes, REQUIRED_ATTRIBUTES[CHECK_ALL], {'all'})
])
def test_fim_reports(folder, name, filetype, content, checkers,
                     ids_to_apply, get_configuration,
                     configure_environment, restart_wazuh,
                     wait_for_initial_scan):
    check_apply_test(ids_to_apply, get_configuration['identifiers'])

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
@pytest.mark.parametrize('folder, checkers, ids_to_apply', [
    # <directories whodata="yes" tags="tag0,tag1,tag2,tag3,tag4,tag5,tag6,tag7,tag8,tag9">/testdir_tags</directories>
    (testdir_tags, REQUIRED_ATTRIBUTES[CHECK_ALL], {'all'})
])
def test_fim_tags(folder, name, filetype, content, checkers, ids_to_apply,
                  get_configuration, configure_environment, restart_wazuh,
                  wait_for_initial_scan):
    check_apply_test(ids_to_apply, get_configuration['identifiers'])

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
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    validate_event(event, checks=checkers)
    assert (defined_tags == event['data']['tags'])
