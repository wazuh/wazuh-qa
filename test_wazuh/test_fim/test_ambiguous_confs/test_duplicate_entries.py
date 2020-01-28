# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, check_time_travel, callback_detect_event, get_fim_mode_param, deepcopy,
                               create_file, REGULAR, generate_params, DEFAULT_TIMEOUT)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=2)]

# variables
test_directories = [os.path.join(PREFIX, 'testdir1')]*2
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_dup_entries.yaml')
testdir1, _ = test_directories


# Configuration

p, m = generate_params(extra_params={'MODULE_NAME': __name__, 'TEST_DIRECTORIES': directory_str})

params, metadata = list(), list()
for mode in ['scheduled', 'realtime', 'whodata']:
    p_fim, m_fim = get_fim_mode_param(mode, key='FIM_MODE2')
    for p_dict, m_dict in zip(p, m):
        p_dict.update(p_fim.items())
        m_dict.update(m_fim.items())
        params.append(deepcopy(p_dict))
        metadata.append(deepcopy(m_dict))

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests


@pytest.mark.parametrize('tags_to_apply', [
   {'ossec_conf'}
])
def test_duplicate_entries(tags_to_apply,
                           get_configuration, configure_environment,
                           restart_syscheckd, wait_for_initial_scan):
    """Checks if syscheckd ignores duplicate entries.
       For instance:
           - The second entry should prevail over the first one.
            <directories realtime="yes">/home/user</directories> (IGNORED)
            <directories whodata="yes">/home/user</directories>
        OR
           - Just generate one event.
            <directories realtime="yes">/home/user,/home/user</directories>
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    file = 'hello'
    mode2 = get_configuration['metadata']['fim_mode2']

    scheduled = mode2 == 'scheduled'
    mode2 = "real-time" if mode2 == "realtime" else mode2

    create_file(REGULAR, testdir1, file, content=' ')

    check_time_travel(scheduled)
    event1 = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()
    event2 = None

    # Check for a second event
    try:
        event2 = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()
    except TimeoutError:
        assert 'added' in event1['data']['type'] and os.path.join(testdir1, file) in event1['data']['path'] \
            and mode2 in event1['data']['mode']

    assert event2 is None, "Error: Multiple events created"
