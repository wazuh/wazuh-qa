# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor, check_apply_test, load_yaml


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
section_configuration_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir'),
                    os.path.join('/', 'testdir1', 'ignore_this'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_ignore, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = [configuration for configuration in
                  load_yaml(section_configuration_path)
                  if 'invalid_no_regex' not in configuration['identifiers']]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder, filename, mode, content, triggers_event, ids_to_apply', [
    (testdir1, 'testfile', 'w', "Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'btestfile', 'wb', b"Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'testfile2', 'w', "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2", "wb", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2.ignore", "wb", b"", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir1, "btestfile2.ignored", "wb", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile', 'w', "Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'btestfile', 'wb', b"Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile2', 'w', "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, "btestfile2", "wb", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, ".ignore.btestfile", "wb", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.ignore", "wb", b"other content", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2, "another.ignored", "wb", b"other content", True, {'valid_regex'}),
    (testdir2_sub, "another.ignore", "wb", b"other content", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2_sub, "another.ignored", "wb", b"other content", True, {'valid_regex'}),
    (testdir2, "another.ignored2", "w", "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.ignore2", "w", "", False, {'valid_regex2', 'valid_regex3'}),
    (testdir1, 'ignore_prefix_test.txt', "w", "test", True, {'valid_regex1', 'valid_regex2', 'valid_regex3', 'valid_regex4'}),
    (testdir1, 'ignore_prefix_test.txt', "w", "test", False, {'valid_regex5'}),
    (testdir1, 'whatever.txt', "w", "test", False, {'valid_empty'}),
    (testdir2, 'whatever2.txt', "w", "test", False, {'valid_empty'})
])
def test_ignore_subdirectory(folder, filename, mode, content, triggers_event,
                             ids_to_apply, get_configuration,
                             configure_environment, restart_wazuh,
                             wait_for_initial_scan):
    """Checks files are ignored in subdirectory according to configuration

       This test is intended to be used with valid ignore configurations

       :param folder string Directory where the file is being created
       :param filename string Name of the file to be created
       :param mode string same as mode in open built-in function
       :param content string, bytes Content to fill the new file
       :param triggers_event bool True if an event must be generated, False otherwise
       :param ids_to_apply set Run test if matchs with a configuration identifier, skip otherwise
    """
    check_apply_test(ids_to_apply, get_configuration['identifiers'])

    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Fetch the n_regular expected events
    try:
        event = wazuh_log_monitor.start(timeout=3,
                                        callback=callback_detect_event).result()
        assert triggers_event
        assert (event['data']['type'] == 'added')
        assert (event['data']['path'] == os.path.join(folder, filename))
    except TimeoutError:
        if triggers_event:
            raise
