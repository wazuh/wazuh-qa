# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
import subprocess
from datetime import timedelta

import pytest

from packages.wazuh_testing.wazuh_testing.fim import CHECK_ALL, DEFAULT_TIMEOUT, FIFO, LOG_FILE_PATH, REGULAR, SOCKET, callback_detect_event, \
    create_file, validate_event, generate_params, is_fim_scan_ended, modify_file_content, check_time_travel, delete_file
from packages.wazuh_testing.wazuh_testing.tools import FileMonitor, TimeMachine, check_apply_test, load_wazuh_configurations, PREFIX

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)

for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))	# Add /testdir1/subdir, /testdir2/subdir ...

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories
timeout = DEFAULT_TIMEOUT

# Extra functions

def stop_create_file_start(folder, file_list, filetype):
    # Stop agent
    p = subprocess.Popen(["service", "wazuh-agent", "stop"])
    p.wait()

    # Create empty files
    for file in file_list:
        create_file(filetype, folder, file, content='')

    # Start agent
    p = subprocess.Popen(["service", "wazuh-agent", "start"])
    p.wait()


# Configurations

monitoring_modes = ['realtime', 'whodata']

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
conf_metadata = {'test_directories': directory_str, 'module_name': __name__}
p, m = generate_params(conf_params, conf_metadata, modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests

@pytest.mark.parametrize('folder, file_list, filetype, content, checkers, tags_to_apply', [
    (testdir1, ['regular0', 'regular1', 'regular2'], REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}, )
])
def test_modify_existing_files_starting_agent_rt_wd(folder, file_list, filetype, content, checkers, tags_to_apply,
                                                 get_configuration, configure_environment):
    """
        Checks if syscheck generates modified alerts for files that exists when starting the agent
        in scheduled mode
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Stop Wazuh, create files and start Wazuh
    stop_create_file_start(folder, file_list, filetype)

    # Modify files
    for file in file_list:
        modify_file_content(folder, file, new_content=content)

    # Monitor log
    wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event, accum_results=len(file_list))

    # Expect modified events
    event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event, accum_results=len(file_list)).result()
    for i, file in enumerate(file_list):
        assert 'modified' in event[i]['data']['type'] and os.path.join(folder, file) in event[i]['data']['path']



@pytest.mark.parametrize('folder, file_list, filetype, content, checkers, tags_to_apply', [
    (testdir1, ['regular0', 'regular1', 'regular2'], REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}, )
])
def test_delete_existing_files_starting_agent_rt_wd(folder, file_list, filetype, content, checkers, tags_to_apply,
                                                 get_configuration, configure_environment):
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Stop Wazuh, create files and start Wazuh
    stop_create_file_start(folder, file_list, filetype)

    # Delete files
    for file in file_list:
        delete_file(folder, file)

    # Monitor log
    wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event, accum_results=len(file_list))

    # Expect modified events
    event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event, accum_results=len(file_list)).result()
    for i, file in enumerate(file_list):
        assert 'deleted' in event[i]['data']['type'] and os.path.join(folder, file) in event[i]['data']['path']
