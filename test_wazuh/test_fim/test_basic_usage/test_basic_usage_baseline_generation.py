# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import paramiko
import pytest

from datetime import datetime, timedelta
from wazuh_testing.fim import (CHECK_ALL, DEFAULT_TIMEOUT, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_event, create_file, validate_event, generate_params, get_log_line, check_time_travel)
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories + [os.path.join(PREFIX, 'noexists')])

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories

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

@pytest.mark.parametrize('folder, name, tags_to_apply', [
    (testdir1, 'file', {'ossec_conf'}),
])
def test_wait_until_baseline(folder, name, tags_to_apply, get_configuration,
                                      configure_environment, restart_syscheckd, wait_for_initial_scan):
    """ Checks if events are appearing after the baseline
        The message 'File integrity monitoring scan ended' informs about the end of the first scan, which generates the baseline

        It creates a file, checks if the baseline has generated before the file addition event, and then if this event has generated.

        :param folder: Name of the monitored folder
        :param name: Name of the file

        * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    create_file(REGULAR, folder, name, content='')
    check_time_travel(scheduled)

    ended_scan = get_log_line('File integrity monitoring scan ended.')
    first_event = get_log_line(r'Sending message to server' if sys.platform == 'win32' else r'Sending event')
    check_time_travel(scheduled)

    try:
        assert ended_scan < first_event
    except AssertionError as e:
        e.args += ('First event before baseline', 0)
        raise
