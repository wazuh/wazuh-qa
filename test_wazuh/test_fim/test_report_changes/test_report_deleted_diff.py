# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import shutil
import sys
from datetime import timedelta

import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, WAZUH_PATH, callback_detect_event,
                               REGULAR, create_file, detect_initial_scan, generate_params)
from wazuh_testing.tools import (PREFIX, FileMonitor, TimeMachine,
                                 load_wazuh_configurations, restart_wazuh_with_new_conf, set_section_wazuh_conf,
                                 check_apply_test)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir_reports'), os.path.join(PREFIX, 'testdir_nodiff')]
nodiff_file = os.path.join(PREFIX, 'testdir_nodiff', 'regular_file')

directory_str = ','.join(test_directories)
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

def change_conf(report_value):
    """" Returns a new ossec configuration with a changed report_value"""
    conf_params, conf_metadata = generate_params({'REPORT_CHANGES': {'report_changes': report_value},
                                                  'TEST_DIRECTORIES': directory_str, 'NODIFF_FILE': nodiff_file,
                                                  'MODULE_NAME': __name__},
                                                 {'report_changes': report_value,
                                                  'test_directories': directory_str, 'nodiff_file': nodiff_file,
                                                  'module_name': __name__})
    return load_wazuh_configurations(configurations_path, __name__,
                                     params=conf_params,
                                     metadata=conf_metadata
                                     )


configurations = change_conf('yes')


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions
def wait_for_event(fim_mode):
    """ Wait for the event to be scanned

    :param fim_mode: FIM mode (scheduled, realtime, whodata)
    :return: None
    """
    if fim_mode == 'scheduled':
        TimeMachine.travel_to_future(timedelta(hours=13))
    # Wait until event is detected
    wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)


def create_and_check_diff(name, directory, fim_mode):
    """ Create a file and check if it is duplicated in diff directory

    :param name: File name
    :param directory: File directory
    :param fim_mode: FIM mode (scheduled, realtime, whodata)
    :return: String with with the duplicated file path (diff)
    """
    create_file(REGULAR, directory, name, content='Sample content')
    wait_for_event(fim_mode)
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
    if sys.platform == 'win32':
        diff_file = os.path.join(diff_file, 'c')
        diff_file = os.path.join(diff_file, directory.strip('C:\\'), name)
    else:
        diff_file = os.path.join(diff_file, directory.strip('/'), name)
    assert (os.path.exists(diff_file)), f'{diff_file} does not exist'
    return diff_file


def check_when_no_report_changes(name, directory, fim_mode, new_conf):
    """ Restart Wazuh without report_changes

    :param name: File name
    :param directory: File directory
    :param fim_mode: FIM mode (scheduled, realtime, whodata)
    :param new_conf: New configuration to apply to syscheck
    :return:
    """
    diff_file = create_and_check_diff(name, directory, fim_mode)
    restart_wazuh_with_new_conf(new_conf)
    # Wait for FIM scan to finish
    detect_initial_scan(wazuh_log_monitor)

    assert (not os.path.exists(diff_file)), f'{diff_file} exists'


def check_when_deleted_directories(name, directory, fim_mode):
    """ Check if the diff directory is empty when the monitored directory is deleted

    :param name: File name
    :param directory: File directory
    :param fim_mode: FIM mode (scheduled, realtime, whodata)
    :return: None
    """
    diff_dir = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
    if sys.platform == 'win32':
        diff_dir = os.path.join(diff_dir, 'c')
        diff_dir = os.path.join(diff_dir, directory.strip('C:\\'), name)
    else:
        diff_dir = os.path.join(diff_dir, directory.strip('/'), name)
    create_and_check_diff(name, directory, fim_mode)
    shutil.rmtree(directory, ignore_errors=True)
    wait_for_event(fim_mode)
    assert (not os.path.exists(diff_dir)), f'{diff_dir} exists'


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
                           restart_syscheckd, wait_for_initial_scan):
    """ Check if duplicated directories in diff are deleted when changing
        report_changes to 'no' or deleting the monitored directories """
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
