# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import shutil

import pytest

from wazuh_testing.fim import *
from wazuh_testing.tools import (FileMonitor, TimeMachine, check_apply_test,
                                 load_wazuh_configurations, set_section_wazuh_conf)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [
    os.path.join('/', 'testdir_reports'),
    os.path.join('/', 'testdir_nodiff')
]
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions
def wait_for_event(tag):
    if tag == {'schedule_report'}:
        TimeMachine.travel_to_future(timedelta(hours=13))
    # Wait until event is detected
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)


def create_and_check_diff(name, directory, tag):
    create_file(REGULAR, name, directory, 'Sample content')
    wait_for_event(tag)
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local',
                             directory.strip('/'), name)
    assert (os.path.exists(diff_file))
    return diff_file


def check_when_no_report_changes(name, directory, tag, new_conf):
    # Restart Wazuh without report_changes
    diff_file = create_and_check_diff(name, directory, tag)
    restart_wazuh_with_new_conf(new_conf, wazuh_log_monitor)
    assert (os.path.exists(diff_file) is False)


def check_when_deleted_directories(name, directory, tag):
    diff_dir = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', directory.strip('/'))
    create_and_check_diff(name, directory, tag)
    shutil.rmtree(directory, ignore_errors=True)
    wait_for_event(tag)
    assert(os.path.exists(diff_dir) is False)


# tests


@pytest.mark.parametrize('tags_to_apply, new_ossec_conf', [
    ({'schedule_report'}, set_section_wazuh_conf(configurations[3].get('section'),
                                                 configurations[3].get('elements'))),
    ({'realtime_report'}, set_section_wazuh_conf(configurations[4].get('section'),
                                                 configurations[4].get('elements'))),
    ({'whodata_report'}, set_section_wazuh_conf(configurations[5].get('section'),
                                                configurations[5].get('elements')))
])
@pytest.mark.parametrize('folder, checkers, delete_dir', [
    (testdir_nodiff, options, True),
    (testdir_reports, options, False)
])
def test_no_report_changes(folder, checkers, delete_dir, tags_to_apply, new_ossec_conf,
                           get_configuration, configure_environment,
                           restart_wazuh, wait_for_initial_scan):
    check_apply_test(tags_to_apply, get_configuration['tags'])

    filename = 'regularfile'

    if delete_dir:
        check_when_deleted_directories(filename, folder, tags_to_apply)
    else:
        check_when_no_report_changes(filename, folder, tags_to_apply, new_ossec_conf)
