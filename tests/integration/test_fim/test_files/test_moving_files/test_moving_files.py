# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, REGULAR, callback_detect_event, create_file)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

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

    Parameters
    ----------
    dirsrc : str
        Source directory.
    dirdst : str
        Target directory.
    filename : str
        File name.
    mod_del_event : str
        Mode of deleted event.
    mod_add_event : str
        Mode of added event.
    """
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

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

@pytest.mark.parametrize('dirsrc, dirdst, filename, mod_del_event, mod_add_event', [
    (testdir1, testdir2, testfile1, whodata, realtime),
    (testdir2, testdir1, testfile2, realtime, whodata)
])
def test_moving_file_to_whodata(dirsrc, dirdst, filename, mod_del_event, mod_add_event, get_configuration,
                                configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test Syscheck's behaviors when moving files from a directory monitored by whodata to another
    monitored by realtime and vice versa.

    Parameters
    ----------
    dirsrc : str
        Source directory.
    dirdst : str
        Target directory.
    filename : str
        File name.
    mod_del_event : str
        Mode of deleted event.
    mod_add_event : str
        Mode of added event.
    """

    os.rename(os.path.join(dirsrc, filename), os.path.join(dirdst, filename))

    check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event)
    check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event)
