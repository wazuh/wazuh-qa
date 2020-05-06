# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.fim import (CHECK_ALL, CHECK_ATTRS, CHECK_GROUP, CHECK_INODE, CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE, CHECK_SUM, LOG_FILE_PATH,
                               REQUIRED_ATTRIBUTES, regular_file_cud, generate_params, create_file, REGULAR,
                               check_time_travel, callback_detect_event, delete_file, modify_file)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'), os.path.join(PREFIX, 'testdir4'),
                    os.path.join(PREFIX, 'testdir5'), os.path.join(PREFIX, 'testdir6'),
                    os.path.join(PREFIX, 'testdir7'), os.path.join(PREFIX, 'testdir8'),
                    os.path.join(PREFIX, 'testdir9'), os.path.join(PREFIX, 'testdir0')]
configurations_path = os.path.join(
    test_data_path, 'wazuh_check_all_windows.yaml' if sys.platform == 'win32' else 'wazuh_check_all.yaml')

testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

# configurations

p, m = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM]),
                    (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM}),
                    (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA1SUM}),
                    (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM}),
                    (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SIZE}),
                    (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_OWNER}),
                    (testdir8, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM})]
if sys.platform == 'win32':
    parametrize_list.extend([
        (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_ATTRS}),
        (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MTIME})
    ])
else:
    parametrize_list.extend([
        (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_GROUP}),
        (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MTIME}),
        (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE})
    ])


@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_all_single(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_initial_scan):
    """
    Test the functionality of `check_all` option when used in conjunction with another check on the same directory,
    having "check_all" to "yes" and the other check to "no".

    Example:
        check_all="yes" check_sum="no"
        check_all="yes" check_mtime="no"
        ...

    Parameters
    ----------
    path : str
        Directory where the file is being created and monitored.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_check_all_single'}, get_configuration['tags'])
    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


if sys.platform == 'win32':
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM}),
                        (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
                        (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
                        (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - {CHECK_SIZE}),
                        (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_ATTRS} - {CHECK_PERM}),
                        (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM} - {CHECK_MTIME}),
                        (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL])
                        ]
else:
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM}),
                        (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
                        (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
                        (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - {CHECK_SIZE}),
                        (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_OWNER} - {CHECK_GROUP}),
                        (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM} - {CHECK_MTIME}),
                        (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE}),
                        (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL])
                        ]


@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_all(path, checkers, get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Test the functionality of `check_all` option when used in conjunction with more than one check on the same directory,
    having "check_all" to "yes" and the other ones to "no".

    Example:
        check_all="yes" check_sum="no" check_md5sum="no"
        check_all="yes" check_perm="yes" check_mtime="no"
        ...

    Parameters
    ----------
    path : str
        Directory where the file is being created and monitored.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_check_all'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


@pytest.mark.parametrize('path, checkers', [(testdir1, {})])
def test_check_all_no(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                      wait_for_initial_scan):
    """
    Test the functionality of `check_all` option when set to no.

    When setting `check_all` to no, only 'type' and 'checksum' attributes should appear in every event. This will
    avoid any modification event.

    Parameters
    ----------
    path : str
        Directory where the file is being created and monitored.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_check_all_no'}, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create regular file and dont expect any check
    file = 'regular'
    create_file(REGULAR, path, file)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    create_event = wazuh_log_monitor.start(callback=callback_detect_event, timeout=15,
                                           error_message='Did not receive expected '
                                                         '"Sending FIM event: ..." event').result()
    assert create_event['data']['type'] == 'added'
    assert list(create_event['data']['attributes'].keys()) == ['type', 'checksum']

    # Delete regular file and dont expect any check. Since it is not using any check, modification events will not
    # be triggered
    modify_file(path, file, 'Sample modification')
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(callback=callback_detect_event, timeout=5)
        raise AttributeError(f'Unexpected event {event}')

    delete_file(path, file)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    delete_event = wazuh_log_monitor.start(callback=callback_detect_event, timeout=15,
                                           error_message='Did not receive expected '
                                                         '"Sending FIM event: ..." event').result()
    assert delete_event['data']['type'] == 'deleted', f'Current value is {delete_event["data"]["type"]}'
    assert list(delete_event['data']['attributes'].keys()) == ['type', 'checksum'], \
        f'Current value is {list(delete_event["data"]["attributes"].keys())}'
