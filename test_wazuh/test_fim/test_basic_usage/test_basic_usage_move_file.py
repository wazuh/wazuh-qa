# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, DEFAULT_TIMEOUT, delete_file
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir1', 'subdir')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2, testdir1_subdir = test_directories

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
conf_metadata = {'test_directories': directory_str, 'module_name': __name__}
p, m = generate_params(conf_params, conf_metadata)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests


@pytest.mark.parametrize('file, file_content, tags_to_apply', [
    ('regular1', '', {'ossec_conf'})
])
@pytest.mark.parametrize('source_folder, target_folder, triggers_delete_event, triggers_add_event', [
    (testdir1, PREFIX, True, False),
    (testdir1, testdir1_subdir, True, True),
    (testdir1, testdir2, True, True),
    (PREFIX, testdir1, False, True),
    (PREFIX, testdir1_subdir, False, True)
])
def test_move_file(file, file_content, tags_to_apply, source_folder, target_folder,
                   triggers_delete_event, triggers_add_event,
                   get_configuration, configure_environment,
                   restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd detects 'added' or 'deleted' events when moving a file.

        :param file str Name of the file to be created
        :param file_content str Content of the file to be created
        :param source_folder str Folder to move the file from
        :param target_folder str Destination folder to move the file to
        :param triggers_delete_event boolean Expects a 'deleted' event in the source folder
        :param triggers_add_event boolean Expects a 'added' event in the target folder
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create file inside folder
    create_file(REGULAR, source_folder, file, content=file_content)

    if source_folder in test_directories:
        check_time_travel(scheduled)
        wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event)

    # Move file to target directory
    os.rename(os.path.join(source_folder, file), os.path.join(target_folder, file))
    check_time_travel(scheduled)

    # Monitor expected events
    events = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT,
                                     callback=callback_detect_event,
                                     accum_results=(triggers_add_event + triggers_delete_event)).result()

    # Expect deleted events
    if isinstance(events, list):
        events_data = [(event['data']['type'],
                        event['data']['path'],
                        os.path.join(source_folder, file) if event['data']['type'] == 'deleted' else os.path.join(
                            target_folder, file))
                       for event in events]
        assert set([event[0] for event in events_data]) == {'deleted', 'added'}
        for _, path, expected_path in events_data:
            assert path == expected_path
    else:
        if triggers_delete_event:
            assert 'deleted' in events['data']['type'] and os.path.join(source_folder, file) in events['data']['path']
        else:
            assert 'added' in events['data']['type'] and os.path.join(target_folder, file) in events['data']['path']

    # Remove file
    delete_file(target_folder, file)
    if target_folder in test_directories:
        check_time_travel(scheduled)
        wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event)
