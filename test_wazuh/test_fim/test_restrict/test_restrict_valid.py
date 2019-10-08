# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import timedelta

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, create_file, REGULAR
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, TimeMachine)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir2, testdir2_sub = test_directories

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


@pytest.mark.parametrize('folder', test_directories)
@pytest.mark.parametrize('filename, mode, content, triggers_event, tags_to_apply', [
    ('.restricted', 'w', "Sample content", True, {'valid_regex1'}),
    ('binary.restricted', 'wb', b"Sample content", True, {'valid_regex1'}),
    ('testfile2', 'w', "", False, {'valid_regex'}),
    ("btestfile2", "wb", b"", False, {'valid_regex'}),
    ('testfile2', 'w', "", True, {'valid_empty'}),
    ("btestfile2", "wb", b"", True, {'valid_empty'}),
    ("restricted", "w", "Test", False, {'valid_regex'}),
    ("myfilerestricted", "w", "", True, {'valid_regex_3'}),
    ("myother_restricted", "wb", b"", True, {'valid_regex_3'})
])
def test_restrict(folder, filename, mode, content, triggers_event, tags_to_apply,
                  get_configuration, configure_environment, restart_wazuh,
                  wait_for_initial_scan):
    """Checks the only files detected are those matching the restrict regex

       This test is intended to be used with valid configurations

       :param folder string Directory where the file is being created
       :param filename string Name of the file to be created
       :param mode string same as mode in open built-in function
       :param content string, bytes Content to fill the new file
       :param triggers_event bool True if an event must be generated, False otherwise
       :param tags_to_apply set Run test if matchs with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create text files
    create_file(REGULAR, filename, folder, content)

    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        # Go ahead in time to let syscheck perform a new scan
        TimeMachine.travel_to_future(timedelta(hours=13))

    try:
        event = wazuh_log_monitor.start(timeout=3,
                                        callback=callback_detect_event).result()
        assert triggers_event
        assert (event['data']['type'] == 'added')
        assert (event['data']['path'] == os.path.join(folder, filename))
    except TimeoutError:
        if triggers_event:
            raise
