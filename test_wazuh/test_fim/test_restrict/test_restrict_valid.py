# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import timedelta

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, DEFAULT_TIMEOUT, callback_detect_event, callback_restricted, create_file, REGULAR, \
    generate_params
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, TimeMachine, PREFIX)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir1', 'subdir'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir2, testdir2_sub = test_directories

directory_str = ','.join([test_directories[0], test_directories[2]])

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params({'TEST_DIRECTORIES': directory_str},
                                             {'test_directories': directory_str})

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
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
                  get_configuration, configure_environment, restart_syscheckd,
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
    create_file(REGULAR, folder, filename, content=content)

    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        # Go ahead in time to let syscheck perform a new scan
        TimeMachine.travel_to_future(timedelta(hours=13))

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT,
                                        callback=callback_detect_event).result()
        assert (event['data']['type'] == 'added'), f'Event type not equal'
        assert (event['data']['path'] == os.path.join(folder, filename)), f'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT,
                                                   callback=callback_restricted).result()
            if ignored_file == os.path.join(folder, filename):
                break
