# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, DEFAULT_TIMEOUT
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

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
    """ Checks if syscheckd detects 'deleted' events from the files contained
        in a folder that is being deleted.

        If we are monitoring /testdir and we have r1, r2, r3 withing /testdir, if we delete /testdir,
        we must see 3 events of the type 'deleted'. One for each one of the regular files.

        :param folder: Directory where the files will be created
        :param file_list: List with the names of the files
        :param  filetype: Type of the files that will be created

        * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create files inside subdir folder
    for file in file_list:
        create_file(filetype, folder, file, content='')

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event, accum_results=len(file_list))

    # Remove folder
    shutil.rmtree(folder, ignore_errors=True)
    check_time_travel(scheduled)

    # Expect deleted events
    event = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event,
                                    accum_results=len(file_list)).result()
    for i, file in enumerate(file_list):
        assert 'deleted' in event[i]['data']['type'] and os.path.join(folder, file) in event[i]['data']['path']
