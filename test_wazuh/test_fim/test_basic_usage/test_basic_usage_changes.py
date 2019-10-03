# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import glob
import os
import re
import time
from datetime import timedelta

import pytest
from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH,
                               callback_detect_end_scan, callback_detect_event,
                               create_file, regular_file_cud, validate_event)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
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
                                           params=[{'FIM_MODE': '', 'MODULE_NAME': __name__},
                                                   {'FIM_MODE': {'realtime': 'yes'}, 'MODULE_NAME': __name__},
                                                   {'FIM_MODE': {'whodata': 'yes'}, 'MODULE_NAME': __name__}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled', 'module_name': __name__},
                                                     {'fim_mode': 'realtime', 'module_name': __name__},
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
@pytest.mark.parametrize('checkers,  tags_to_apply', [
    (options, {'ossec_conf'}),
])
def test_regular_file_changes(folder, checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_wazuh, wait_for_initial_scan):
    """ Checks if syscheckd detects regular file changes (add, modify, delete)"""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    n_regular = 3
    min_timeout = 3
    is_scheduled = False

    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        is_scheduled = True
    regular_file_cud(folder, is_scheduled, n_regular, min_timeout, wazuh_log_monitor, checkers)
