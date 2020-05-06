# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
from collections import Counter

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
directory_str = ','.join(test_directories)
for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[2:]

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

@pytest.mark.parametrize('folder, file_list, filetype, tags_to_apply', [
    (testdir1, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},),
    (testdir2, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},)
])
def test_delete_folder(folder, file_list, filetype, tags_to_apply,
                       get_configuration, configure_environment,
                       restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheckd detects 'deleted' events from the files contained
    in a folder that is being deleted.

    If we are monitoring /testdir and we have r1, r2, r3 withing /testdir, if we delete /testdir,
    we must see 3 events of the type 'deleted'. One for each one of the regular files.

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    file_list : list
        Names of the files.
    filetype : str
        Type of the files that will be created.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    # Create files inside subdir folder
    for file in file_list:
        create_file(filetype, folder, file, content='')

    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            accum_results=len(file_list), error_message='Did not receive expected '
                                                                        '"Sending FIM event: ..." event').result()
    for ev in events:
        validate_event(ev, mode=mode)

    # Remove folder
    shutil.rmtree(folder, ignore_errors=True)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    # Expect deleted events
    event_list = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event',
                                         accum_results=len(file_list)).result()
    path_list = set([event['data']['path'] for event in event_list])
    counter_type = Counter([event['data']['type'] for event in event_list])
    for ev in events:
        validate_event(ev, mode=mode)

    assert counter_type['deleted'] == len(file_list), f'Number of "deleted" events should be {len(file_list)}'

    for file in file_list:
        assert os.path.join(folder, file) in path_list, f'File {file} not found within the events'
