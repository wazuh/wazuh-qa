# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import shutil
import sys
import time

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, WAZUH_PATH, callback_detect_event,
                               REGULAR, create_file, generate_params, detect_initial_scan, check_time_travel)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import restart_wazuh_with_new_conf

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

test_directories = [os.path.join(PREFIX, 'testdir_reports'), os.path.join(PREFIX, 'testdir_nodiff')]
testdir_reports, testdir_nodiff = test_directories
directory_str = ','.join(test_directories)

nodiff_file = os.path.join(PREFIX, 'testdir_nodiff', 'regular_file')
FILE_NAME = 'regularfile'


# configurations

def change_conf(report_value):
    """"Return a new ossec configuration with a changed report_value"""
    conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': report_value},
                                                               'TEST_DIRECTORIES': directory_str,
                                                               'NODIFF_FILE': nodiff_file,
                                                               'MODULE_NAME': __name__})

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

def detect_fim_scan(file_monitor):
    """
    Detect initial scan when restarting Wazuh.

    Parameters
    ----------
    file_monitor : FileMonitor
        File log monitor to detect events
    """
    detect_initial_scan(file_monitor)
    if sys.platform == 'win32':
        time.sleep(5)


def wait_for_event(fim_mode):
    """Wait for the event to be scanned.

    Parameters
    ----------
    fim_mode : str
        FIM mode (scheduled, realtime, whodata)
    """
    check_time_travel(time_travel=fim_mode == 'scheduled', monitor=wazuh_log_monitor)

    # Wait until event is detected
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event')


def create_and_check_diff(name, path, fim_mode):
    """Create a file and check if it is duplicated in diff directory.

    Parameters
    ----------
    name : str
        Name of the file to be created
    path : str
        path where the file will be created
    fim_mode : str
        FIM mode (scheduled, realtime, whodata)

    Returns
    -------
    str
        String with the duplicated file path (diff)
    """
    create_file(REGULAR, path, name, content='Sample content')
    wait_for_event(fim_mode)
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
    if sys.platform == 'win32':
        diff_file = os.path.join(diff_file, 'c')
        diff_file = os.path.join(diff_file, re.match(r'^[a-zA-Z]:(\\){1,2}(\w+)(\\){0,2}$', path).group(2), name)
    else:
        diff_file = os.path.join(diff_file, path.strip('/'), name)
    assert os.path.exists(diff_file), f'{diff_file} does not exist'
    return diff_file


def disable_report_changes():
    """Change the `report_changes` value in the `ossec.conf` file and then restart `Syscheck` to apply the changes."""
    new_conf = change_conf(report_value='no')
    new_ossec_conf = set_section_wazuh_conf(new_conf[0].get('sections'))
    restart_wazuh_with_new_conf(new_ossec_conf)
    # Wait for FIM scan to finish
    detect_fim_scan(wazuh_log_monitor)


# tests

@pytest.mark.parametrize('path', [testdir_nodiff])
def test_report_when_deleted_directories(path, get_configuration, configure_environment, restart_syscheckd,
                                         wait_for_initial_scan):
    """Check if the diff directory is empty when the monitored directory is deleted.

    Parameters
    ----------
    path : str
        Path to the file to be deleted
    """
    fim_mode = get_configuration['metadata']['fim_mode']
    diff_dir = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')

    if sys.platform == 'win32':
        diff_dir = os.path.join(diff_dir, 'c')
        diff_dir = os.path.join(diff_dir, re.match(r'^[a-zA-Z]:(\\){1,2}(\w+)(\\){0,2}$', path).group(2), FILE_NAME)
    else:
        diff_dir = os.path.join(diff_dir, path.strip('/'), FILE_NAME)
    create_and_check_diff(FILE_NAME, path, fim_mode)
    shutil.rmtree(path, ignore_errors=True)
    wait_for_event(fim_mode)
    assert not os.path.exists(diff_dir), f'{diff_dir} exists'


@pytest.mark.parametrize('path', [testdir_reports])
def test_no_report_changes(path, get_configuration, configure_environment,
                           restart_syscheckd, wait_for_initial_scan):
    """Check if duplicated directories in diff are deleted when changing `report_changes` to 'no' or deleting the
    monitored directories.

    Parameters
    ----------
    path : str
        Path to the file
    """
    fim_mode = get_configuration['metadata']['fim_mode']
    diff_file = create_and_check_diff(FILE_NAME, path, fim_mode)
    backup_conf = get_wazuh_conf()

    try:
        disable_report_changes()
        assert not os.path.exists(diff_file), f'{diff_file} exists'
    finally:
        # Restore the original conf file so as not to interfere with other tests
        restart_wazuh_with_new_conf(backup_conf)
        detect_fim_scan(wazuh_log_monitor)


def test_report_changes_after_restart(get_configuration, configure_environment, restart_syscheckd,
                                      wait_for_initial_scan):
    """Check if duplicated directories in diff are deleted when restarting syscheck.

    The duplicated directories in diff will be removed after Syscheck restarts but will be created again if the report
    changes is still active. To avoid this we disable turn off report_changes option before restarting Syscheck to
    ensure directories won't be created again.
    """
    fim_mode = get_configuration['metadata']['fim_mode']

    # Create a file in the monitored path to force the creation of a report in diff
    diff_file_path = create_and_check_diff(FILE_NAME, testdir_reports, fim_mode)

    backup_conf = get_wazuh_conf()
    try:
        disable_report_changes()
        assert not os.path.exists(diff_file_path), f'{diff_file_path} exists'
    finally:
        # Restore the original conf file so as not to interfere with other tests
        restart_wazuh_with_new_conf(backup_conf)
        detect_fim_scan(wazuh_log_monitor)
