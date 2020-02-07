# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import pytest
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2, testdir3 = test_directories

# marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# This directory won't be monitored
testdir4 = os.path.join(PREFIX, 'testdir4')

# configurations
conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests


def extra_configuration_before_yield():
    """Create subdirs before restarting Wazuh."""
    create_file(REGULAR, os.path.join(testdir1, 'subdir'), 'regular1', content='')
    create_file(REGULAR, os.path.join(testdir3, 'subdir2'), 'regular2', content='')
    create_file(REGULAR, os.path.join(testdir4, 'subdir'), 'regular1', content='')


def extra_configuration_after_yield():
    """Delete subdir directory after finishing the module execution since it's not monitored."""
    shutil.rmtree(os.path.join(PREFIX, 'subdir'), ignore_errors=True)


@pytest.mark.parametrize('source_folder, target_folder, subdir, tags_to_apply, \
                triggers_delete_event, triggers_add_event', [
    (testdir4, testdir2, 'subdir', {'ossec_conf'}, False, True),
    (testdir1, PREFIX, 'subdir', {'ossec_conf'}, True, False),
    (testdir3, testdir2, 'subdir2', {'ossec_conf'}, True, True),
])
def test_move_file(source_folder, target_folder, subdir, tags_to_apply,
                   triggers_delete_event, triggers_add_event,
                   get_configuration, configure_environment,
                   restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheckd detects 'added' or 'deleted' events when moving a
    subfolder from a folder to another one.

    Parameters
    ----------
    subdir : str
        Name of the subdir to be moved.
    source_folder : str
        Folder to move the file from.
    target_folder : str
        Destination folder to move the file to.
    triggers_delete_event : bool
        Expect a 'deleted' event in the source folder.
    triggers_add_event : bool
        Expect a 'added' event in the target folder.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Move folder to target directory
    os.rename(os.path.join(source_folder, subdir), os.path.join(target_folder, subdir))
    check_time_travel(scheduled)

    # Monitor expected events
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     accum_results=(triggers_add_event + triggers_delete_event)).result()

    # Expect deleted events
    if isinstance(events, list):
        events_data = [(event['data']['type'],
                        os.path.dirname(event['data']['path']),
                        os.path.join(source_folder, subdir) if event['data']['type'] == 'deleted' else os.path.join(
                            target_folder, subdir))
                       for event in events]
        assert set([event[0] for event in events_data]) == {'deleted', 'added'}
        for _, path, expected_path in events_data:
            assert path == expected_path
    else:
        if triggers_delete_event:
            assert 'deleted' in events['data']['type'] and os.path.join(source_folder, subdir) \
                   in os.path.dirname(events['data']['path'])
        if triggers_add_event:
            assert 'added' in events['data']['type'] and os.path.join(target_folder, subdir) \
                   in os.path.dirname(events['data']['path'])
