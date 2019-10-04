# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import shutil
from datetime import timedelta

import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, WAZUH_PATH, callback_detect_event,
                               REGULAR, create_file, restart_wazuh_with_new_conf)
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


def change_conf(report_value):
    """" Returns a new ossec configuration with a changed report_value"""
    return load_wazuh_configurations(configurations_path, __name__,
                                     params=[{'FIM_MODE': '',
                                              'REPORT_CHANGES': {'report_changes': report_value},
                                              'MODULE_NAME': __name__},
                                             {'FIM_MODE': {'realtime': 'yes'},
                                              'REPORT_CHANGES': {'report_changes': report_value},
                                              'MODULE_NAME': __name__},
                                             {'FIM_MODE': {'whodata': 'yes'},
                                              'REPORT_CHANGES': {'report_changes': report_value},
                                              'MODULE_NAME': __name__}
                                             ],
                                     metadata=[{'fim_mode': 'scheduled', 'report_changes': report_value,
                                                'module_name': __name__},
                                               {'fim_mode': 'realtime', 'report_changes': report_value,
                                                'module_name': __name__},
                                               {'fim_mode': 'whodata', 'report_changes': report_value,
                                                'module_name': __name__}
                                               ]
                                     )


configurations = change_conf('yes')


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions
def wait_for_event(fim_mode):
    """ Wait for the event to be scanned"""
    if fim_mode == 'scheduled':
        TimeMachine.travel_to_future(timedelta(hours=13))
    # Wait until event is detected
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)


def create_and_check_diff(name, directory, fim_mode):
    """ Create a file and check if it is duplicated in diff directory"""
    create_file(REGULAR, name, directory, 'Sample content')
    wait_for_event(fim_mode)
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local',
                             directory.strip('/'), name)
    assert (os.path.exists(diff_file))
    return diff_file


def check_when_no_report_changes(name, directory, fim_mode, new_conf):
    # Restart Wazuh without report_changes
    diff_file = create_and_check_diff(name, directory, fim_mode)
    restart_wazuh_with_new_conf(new_conf, wazuh_log_monitor)
    assert (os.path.exists(diff_file) is False)


def check_when_deleted_directories(name, directory, fim_mode):
    # Check if the diff directory is empty when the monitored directory is deleted
    diff_dir = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', directory.strip('/'))
    create_and_check_diff(name, directory, fim_mode)
    shutil.rmtree(directory, ignore_errors=True)
    wait_for_event(fim_mode)
    assert (os.path.exists(diff_dir) is False)


# tests


@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_report'},
])
@pytest.mark.parametrize('folder, checkers, delete_dir', [
    (testdir_nodiff, options, True),
    (testdir_reports, options, False)
])
def test_no_report_changes(folder, checkers, delete_dir, tags_to_apply,
                           get_configuration, configure_environment,
                           restart_wazuh, wait_for_initial_scan):
    """ Check if duplicated directories in diff are deleted when changing
        report_changes to 'no' or deleting the monitored directories"""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    filename = 'regularfile'
    fim_mode = get_configuration['metadata']['fim_mode']
    if delete_dir:
        check_when_deleted_directories(filename, folder, fim_mode)
    else:
        new_conf = change_conf(report_value='no')
        new_ossec_conf = set_section_wazuh_conf(new_conf[0].get('section'),
                                                new_conf[0].get('elements'))
        check_when_no_report_changes(filename, folder, fim_mode, new_ossec_conf)
