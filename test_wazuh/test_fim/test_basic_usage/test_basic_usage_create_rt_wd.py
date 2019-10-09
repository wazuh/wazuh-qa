# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import time
from datetime import timedelta

import pytest

from wazuh_testing.fim import (CHECK_ALL, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_end_scan, callback_detect_event,
                               create_file, validate_event)
from wazuh_testing.tools import (FileMonitor, TimeMachine, check_apply_test,
                                 load_wazuh_configurations)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': {'realtime': 'yes'}, 'MODULE_NAME': __name__},
                                                   {'FIM_MODE': {'whodata': 'yes'}, 'MODULE_NAME': __name__}
                                                   ],
                                           metadata=[{'fim_mode': 'realtime', 'module_name': __name__},
                                                     {'fim_mode': 'whodata', 'module_name': __name__}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests


@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('name, filetype, content, checkers, tags_to_apply', [
    ('file', REGULAR, 'Sample content', options, {'ossec_conf'}),
    ('file2', REGULAR, b'Sample content', options, {'ossec_conf'}),
    ('socket_file', SOCKET, '', options, {'ossec_conf'}),
    ('file3', REGULAR, '', options, {'ossec_conf'}),
    ('fifo_file', FIFO, '', options, {'ossec_conf'}),
    ('file4', REGULAR, b'', options, {'ossec_conf'}),
])
def test_create_file_realtime_whodata(folder, name, filetype, content, checkers, tags_to_apply,
                                      get_configuration, configure_environment, restart_wazuh,
                                      wait_for_initial_scan):
    """ Checks if a special or regular file creation is detected by syscheck using realtime and whodata monitoring"""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files
    create_file(filetype, name, folder, content)

    if filetype == REGULAR:
        # Wait until event is detected
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        validate_event(event, checkers)
    else:
        with pytest.raises(TimeoutError):
            assert wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
