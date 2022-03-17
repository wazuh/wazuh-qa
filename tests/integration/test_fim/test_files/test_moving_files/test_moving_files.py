'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM detects
       moving files from one directory using the 'whodata' monitoring mode to another using
       the 'realtime' monitoring mode and vice versa.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_moving_files

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_moving_files
'''
import os
import sys

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

mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")
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
@mark_skip_agentWindows
def test_moving_file_to_whodata(dirsrc, dirdst, filename, mod_del_event, mod_add_event, get_configuration,
                                configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when moving files from a directory
                 monitored by 'whodata' to another monitored by 'realtime' and vice versa. For this purpose,
                 the test will monitor two folders using both FIM monitoring modes and create a testing file
                 inside each one. Then, it will rename the testing file of the target folder using the name
                 of the one inside the source folder. Finally, the test will verify that the FIM events
                 generated to match the monitoring mode used in the folders.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - dirsrc:
            type: str
            brief: Path to the source directory where the testing file will be deleted.
        - dirdst:
            type: str
            brief: Path to the target directory where the testing file will be added.
        - filename:
            type: str
            brief: Name of the testing file.
        - mod_del_event:
            type: str
            brief: Monitoring mode of FIM 'deleted' event.
        - mod_add_event:
            type: str
            brief: Monitoring mode of FIM 'added' event.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that the 'mode' field in FIM 'deleted' events match with one used
          in the source folder of moved files.
        - Verify that the 'mode' field in FIM 'added' events match with one used
          in the target folder of moved files.

    input_description: A test case (monitoring_realtime) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'deleted' events)

    tags:
        - realtime
        - who_data
    '''
    os.rename(os.path.join(dirsrc, filename), os.path.join(dirdst, filename))

    check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event)
    check_event(dirsrc, dirdst, filename, mod_del_event, mod_add_event)
