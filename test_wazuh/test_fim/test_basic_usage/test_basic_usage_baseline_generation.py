# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from time import time

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, REGULAR, callback_detect_event, callback_detect_end_scan, create_file,
                               generate_params)
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX

# Marks

pytestmark = pytest.mark.tier(level=0)

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
p, m = generate_params(extra_params=conf_params, extra_metadata=conf_metadata, modes=['scheduled', 'realtime'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def callback_detect_event_before_end_scan(line):
    ended_scan = callback_detect_end_scan(line)
    if ended_scan is None:
        event = callback_detect_event(line)
        assert event is None, 'Event detected before end scan'
        return None
    else:
        return True


def extra_configuration_before_yield():
    for _ in range(1000):
        create_file(REGULAR, testdir1, f'test_{int(round(time() * 10**6))}', content='')
        create_file(REGULAR, testdir2, f'test_{int(round(time() * 10**6))}', content='')


def test_wait_until_baseline(get_configuration, configure_environment, restart_syscheckd):
    """ Checks if events are appearing after the baseline
        The message 'File integrity monitoring scan ended' informs about the end of the first scan, which generates the baseline

        It creates a file, checks if the baseline has generated before the file addition event, and then if this event has generated.


        * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    # Create a file during initial scan to check if the event is logged after the 'scan ended' message
    create_file(REGULAR, testdir1, f'test_{int(round(time() * 10**6))}', content='')

    wazuh_log_monitor.start(timeout=120, callback=callback_detect_event_before_end_scan)
