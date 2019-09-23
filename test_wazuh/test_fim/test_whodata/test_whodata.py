# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, REGULAR, callback_detect_event,
                               create_file, delete_file, modify_file,
                               validate_event)
from wazuh_testing.tools import FileMonitor, load_yaml


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

section_configuration_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3'),
                    os.path.join('/', 'testdir4'), os.path.join('/', 'testdir5'), os.path.join('/', 'testdir6'),
                    os.path.join('/', 'testdir7'), os.path.join('/', 'testdir8'), os.path.join('/', 'testdir9'),
                    os.path.join('/', 'testdir0')]
testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

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
@pytest.mark.parametrize('folder, checkers, checks', [
    # <directories whodata="yes" check_all="yes" check_sum="no">/testdir1</directories>
    (testdir1, {"hash_md5": "no", "hash_sha1": "no", "hash_sha256": "no"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_md5sum="no">/testdir2</directories>
    (testdir2, {"hash_md5": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_sha1sum="no">/testdir3</directories>
    (testdir3, {"hash_sha1": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_sha256sum="no">/testdir4</directories>
    (testdir4, {"hash_sha256": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_size="no">/testdir5</directories>
    (testdir5, {"size": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_owner="no">/testdir6</directories>
    (testdir6, {"uid": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_group="no">/testdir7</directories>
    (testdir7, {"gid": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_perm="no">/testdir8</directories>
    (testdir8, {"perm": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_mtime="no">/testdir9</directories>
    (testdir9, {"mtime": "except"}, {'conf1'}),
    # <directories whodata="yes" check_all="yes" check_inode="no">/testdir0</directories>
    (testdir0, {"inode": "except"}, {'conf1'})
])
def test_fim_whodata(folder, name, filetype, content, checkers, checks,
                     get_configuration, configure_environment, restart_wazuh,
                     wait_for_initial_scan):
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    # Create file
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    validate_event(checkers, event)

    # Modify file
    modify_file(folder, name, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    validate_event(checkers, event)

    # Delete file
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    validate_event(checkers, event)
