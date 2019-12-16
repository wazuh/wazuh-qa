# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, check_time_travel, callback_detect_event, 
    create_file, REGULAR, detect_initial_scan, delete_file)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, 
    restart_wazuh_with_new_conf, set_section_wazuh_conf)

# variables

if sys.platform == 'win32':
    test_directories = [os.path.join('c:', os.sep, 'testdir1'), os.path.join('c:', os.sep, 'testdir1')]
    directory_str = "c:\\testdir1,c:\\testdir2,c:\\noexists"

else:
    test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir1')]
    directory_str = "/testdir1,/testdir1,/noexists"

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, _ = test_directories
file = 'hello'


def mode_format(mode):
    if mode is not 'scheduled':
        return {mode:'yes'}
    else:
        return ''


def change_conf(mode=None, mode2=None):
    return load_wazuh_configurations(configurations_path, __name__,
                                        params=[{'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__ , 'FIM_MODE': mode_format(mode),
                                                 'TEST_DIRECTORIES2': directory_str, 'FIM_MODE2': mode_format(mode2)},
                                                ],
                                        metadata=[{'test_directories': directory_str, 'module_name': __name__, 'fim_mode': mode, 
                                                   'test_directories2': directory_str, 'fim_mode2': mode2}
                                                 ]
                                    )

# Not used at all. Just to satisfy the called fixtures.
configurations = change_conf('scheduled', 'scheduled') 

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

@pytest.mark.parametrize('mode, mode2, checkers, tags_to_apply', [
    ('whodata', 'realtime', {CHECK_ALL}, {'ossec_conf'}),
    ('realtime', 'scheduled', {CHECK_ALL}, {'ossec_conf'}),
    ('whodata', 'whodata',  {CHECK_ALL}, {'ossec_conf'}),
    ('scheduled', 'whodata', {CHECK_ALL}, {'ossec_conf'})
])
def test_duplicate_entries( mode, mode2, checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd ignores duplicate entries. 
        For instance:
            - The second entry should prevail over the first one.
            <directories realtime="yes">/home/user</directories> (NO)
            <directories whodata="yes">/home/user</directories>  (YES)
        OR
            - Just generate one event.
            <directories realtime="yes">/home/user,/home/user</directories>

    :param mode: First entry's mode and the one which syscheck should skip.
    :param mode2: Second entry's mode and the one which syscheck should choose.
    """

    # To avoid 'modified' flag (The file already exists)
    delete_file(testdir1, file) 
    
    new_conf = change_conf(mode, mode2)
    new_ossec_conf = set_section_wazuh_conf(new_conf[0].get('section'), 
                                                       new_conf[0].get('elements'))

    restart_wazuh_with_new_conf(new_ossec_conf)
    detect_initial_scan(wazuh_log_monitor)

    scheduled = mode2 == 'scheduled'
    mode2 = "real-time" if  mode2 == "realtime" else mode2 

    create_file(REGULAR, testdir1, file, content=' ')
    
    check_time_travel(scheduled)
    event1 = wazuh_log_monitor.start(timeout=30, callback=callback_detect_event).result()
    event2 = None

    try: # Check for a second event
        event2 = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event).result()
    except TimeoutError:
        assert 'added' in event1['data']['type'] and os.path.join(testdir1, file) in event1['data']['path'] \
    and mode2 in event1['data']['mode']

    assert event2 is None, "Error: Multiple events created"


    