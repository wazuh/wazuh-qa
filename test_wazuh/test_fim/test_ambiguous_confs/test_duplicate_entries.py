# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, check_time_travel, callback_detect_event, 
    create_file, REGULAR, detect_initial_scan, delete_file, generate_params)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, 
    restart_wazuh_with_new_conf, set_section_wazuh_conf, PREFIX)

# variables
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join([os.path.join(PREFIX, 'testdir1')] + [os.path.join(PREFIX, 'testdir1')])
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_dup_entries.yaml')
testdir1, _ = test_directories
file = 'hello'

# Convert the mode string into an ossec.conf valid format value
def mode_format(mode):
    if mode is not 'scheduled':
        return {mode:'yes'}
    else:
        return ''


# Configuration
conf_params = [
            {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__, 'FIM_MODE':mode_format('whodata'), 
            'TEST_DIRECTORIES2': directory_str, 'FIM_MODE2':mode_format('realtime')},
            {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__, 'FIM_MODE':mode_format('realtime'),
            'TEST_DIRECTORIES2': directory_str, 'FIM_MODE2':mode_format('scheduled')},
            {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__, 'FIM_MODE':mode_format('whodata'),
            'TEST_DIRECTORIES2': directory_str, 'FIM_MODE2':mode_format('whodata')},
            {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__, 'FIM_MODE':mode_format('scheduled'),
            'TEST_DIRECTORIES2': directory_str, 'FIM_MODE2':mode_format('whodata')}
            ]
conf_metadata = [
            {'module_name': __name__, 'fim_mode':'whodata', 'fim_mode2':'realtime'},
            {'module_name': __name__, 'fim_mode':'realtime', 'fim_mode2':'scheduled'},
            {'module_name': __name__, 'fim_mode':'whodata', 'fim_mode2':'whodata'},
            {'module_name': __name__, 'fim_mode':'scheduled', 'fim_mode2':'whodata'}
            ]

configurations = load_wazuh_configurations(configurations_path, 
                                    __name__, params=conf_params, metadata=conf_metadata) 

# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

@pytest.mark.parametrize('checkers, tags_to_apply', [
   ({CHECK_ALL}, {'ossec_conf'}),
])
def test_duplicate_entries(  checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd ignores duplicate entries. 
        For instance:
            - The second entry should prevail over the first one.
            <directories realtime="yes">/home/user</directories> (IGNORED)
            <directories whodata="yes">/home/user</directories>  
        OR
            - Just generate one event.
            <directories realtime="yes">/home/user,/home/user</directories>

    :param mode2: Second entry's mode and the one which syscheck should choose.
    """
    mode2 = get_configuration['metadata']['fim_mode2']

    scheduled = mode2 == 'scheduled'
    mode2 = "real-time" if  mode2 == "realtime" else mode2 

    create_file(REGULAR, testdir1, file, content=' ')

    check_time_travel(scheduled)
    event1 = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()
    event2 = None

    try: # Check for a second event
        event2 = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()
    except TimeoutError:
        assert 'added' in event1['data']['type'] and os.path.join(testdir1, file) in event1['data']['path'] \
    and mode2 in event1['data']['mode']

    assert event2 is None, "Error: Multiple events created"
