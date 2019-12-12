# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, REGULAR, DEFAULT_TIMEOUT, callback_detect_event, create_file)
from wazuh_testing.tools import FileMonitor, PREFIX, load_wazuh_configurations

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
testdir1, testdir2 = test_directories
testfile1 = 'file1'
testfile2 = 'file2'
whodata = 'whodata'
realtime = 'realtime'
added = 'added'
deleted = 'deleted'

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# Internal functions

def extra_configuration_before_yield():
    """
    Create /testdir1/file1 and /testdir2/file2 before execute test
    """

    create_file(REGULAR, testdir1, testfile1, content='')
    create_file(REGULAR, testdir2, testfile2, content='')


def check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event):
    """
    Check the event has been generated
    :param dirsrc: Source directory
    :param dirdst: Target directory
    :param filename: File name
    :param mod_del_event: Mode of deleted event
    :param mod_add_event: Mode of added event
    """
    event = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()

    try:
        assert (event['data']['mode'] == mod_del_event and event['data']['type'] == deleted and
                os.path.join(dirsrc, filename) in event['data']['path'])
    except AssertionError:
        if (event['data']['mode'] != mod_add_event and event['data']['type'] != added and
                os.path.join(dirdst, filename) in event['data']['path']):
            raise AssertionError(f'Event not found')


# Fixture

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """
    Get configurations from the module.
    """
    return request.param


# Test

@pytest.mark.linux
@pytest.mark.win32
@pytest.mark.parametrize('dirsrc, dirdst, filename, mod_del_event, mod_add_event', [
    (testdir1, testdir2, testfile1, whodata, realtime),
    (testdir2, testdir1, testfile2, realtime, whodata)
])
def test_moving_file_to_whodata(dirsrc, dirdst, filename, mod_del_event, mod_add_event, get_configuration,
                                configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Test Syscheck's behaviors when moving files from a directory monitored by whodata to another
    monitored by realtime and vice versa.

    :param dirsrc: Source directory
    :param dirdst: Target directory
    :param filename: File name
    :param mod_del_event: Added event mode
    :param mod_add_event: Deleted event mode
    """

    os.rename(os.path.join(dirsrc, filename), os.path.join(dirdst, filename))

    check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event)
    check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event)
