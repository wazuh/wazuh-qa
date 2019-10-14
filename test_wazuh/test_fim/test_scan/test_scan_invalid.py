# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_configuration_error)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_times = 'invalid_time'
scan_days = 'invalid_day'
# configurations


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'SCAN_TIME': scan_times, 'SCAN_DAY': ''},
                                                   {'SCAN_TIME': '', 'SCAN_DAY': scan_days},
                                                   ],
                                           metadata=[{'scan_time': scan_times, 'scan_day': ''},
                                                     {'scan_time': '', 'scan_day': scan_days},
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'scan_invalid'}
])
def test_scan_invalid(tags_to_apply,
                      get_configuration, configure_environment,
                      restart_syscheckd):
    """ Check if there is a scan at a certain time """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error)
