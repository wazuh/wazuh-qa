# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import timedelta

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, callback_ignore, create_file, REGULAR
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, TimeMachine

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir'),
                    os.path.join('/', 'testdir1', 'ignore_this'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_ignore, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': ''},
                                                   {'FIM_MODE': {'realtime': 'yes'}},
                                                   {'FIM_MODE': {'whodata': 'yes'}}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled'},
                                                     {'fim_mode': 'realtime'},
                                                     {'fim_mode': 'whodata'}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder, filename, content, triggers_event, tags_to_apply', [
    (testdir1, 'testfile', "Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'btestfile', b"Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'testfile2', "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2.ignore", b"", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir1, "btestfile2.ignored", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile', "Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'btestfile', b"Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile2', "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, "btestfile2", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, ".ignore.btestfile", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.ignore", b"other content", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2, "another.ignored", b"other content", True, {'valid_regex'}),
    (testdir2_sub, "another.ignore", b"other content", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2_sub, "another.ignored", b"other content", True, {'valid_regex'}),
    (testdir2, "another.ignored2", "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.ignore2", "", False, {'valid_regex2', 'valid_regex3'}),
    (testdir1, 'ignore_prefix_test.txt', "test", True, {'valid_regex1', 'valid_regex2', 'valid_regex3', 'valid_regex4'}),
    (testdir1, 'ignore_prefix_test.txt', "test", False, {'valid_regex5'}),
    (testdir1, 'whatever.txt', "test", False, {'valid_empty'}),
    (testdir2, 'whatever2.txt', "test", False, {'valid_empty'}),
    (testdir1, 'mytest', "test", True, {'negation_regex'}),
    (testdir1, 'othername', "test", False, {'negation_regex'})
])
def test_ignore_subdirectory(folder, filename, content, triggers_event,
                             tags_to_apply, get_configuration,
                             configure_environment, restart_syscheckd,
                             wait_for_initial_scan):
    """Checks files are ignored in subdirectory according to configuration

       This test is intended to be used with valid ignore configurations

       :param folder string Directory where the file is being created
       :param filename string Name of the file to be created
       :param content string, bytes Content to fill the new file
       :param triggers_event bool True if an event must be generated, False otherwise
       :param tags_to_apply set Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create text files
    create_file(REGULAR, filename, folder, content)

    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        # Go ahead in time to let syscheck perform a new scan
        TimeMachine.travel_to_future(timedelta(hours=13))

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=3,
                                        callback=callback_detect_event).result()
        assert (event['data']['type'] == 'added')
        assert (event['data']['path'] == os.path.join(folder, filename))
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=3,
                                                   callback=callback_ignore).result()
            if ignored_file == os.path.join(folder, filename):
                break
