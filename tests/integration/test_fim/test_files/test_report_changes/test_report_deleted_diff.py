'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM manages properly
       the 'diff' folder created in the 'queue/diff/local' directory when removing a monitored
       folder or the 'report_changes' option is disabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_report_changes

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_report_changes
'''
import os
import re
import shutil
import sys
import time

import pytest
from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, load_wazuh_configurations
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import restart_wazuh_with_new_conf
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.modules.fim.utils import generate_params
from wazuh_testing.modules.fim.event_monitor import detect_initial_scan, callback_detect_event
from test_fim.common import make_diff_file_path

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables
local_internal_options = FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS
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
                                                               'NODIFF_FILE': nodiff_file})

    return load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


configurations = change_conf('yes')


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions

def detect_fim_scan(file_monitor, fim_mode):
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
    elif fim_mode == 'scheduled':
        time.sleep(1)


def wait_for_event(fim_mode):
    """Wait for the event to be scanned.

    Parameters
    ----------
    fim_mode : str
        FIM mode (scheduled, realtime, whodata)
    """

    # Wait until event is detected
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event')


def create_file_and_check_diff(name, path, fim_mode):
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

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event')

    diff_file = make_diff_file_path(path, name)
    assert os.path.exists(diff_file), f'{diff_file} does not exist'
    return diff_file


def disable_report_changes(fim_mode):
    """Change the `report_changes` value in the `ossec.conf` file and then restart `Syscheck` to apply the changes."""
    new_conf = change_conf(report_value='no')
    new_ossec_conf = set_section_wazuh_conf(new_conf[0].get('sections'))

    restart_wazuh_with_new_conf(new_ossec_conf)
    # Wait for FIM scan to finish
    detect_fim_scan(wazuh_log_monitor, fim_mode)


# tests

@pytest.mark.parametrize('path', [testdir_nodiff])
def test_report_when_deleted_directories(path, get_configuration, configure_environment,
                                         configure_local_internal_options_module, restart_syscheckd,
                                         wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon deletes the 'diff' folder created in the 'queue/diff/local'
                 directory when removing a monitored folder and the 'report_changes' option is enabled.
                 For this purpose, the test will monitor a directory and add a testing file inside it. Then,
                 it will check if a 'diff' file is created for the modified testing file. Finally, the test
                 will remove the monitored folder, wait for the FIM 'deleted' event, and verify that
                 the corresponding 'diff' folder is deleted.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - path:
            type: str
            brief: Path to the testing file to be deleted.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that the FIM event is generated when removing the monitored folder.
        - Verify that FIM adds the 'diff' file in the 'queue/diff/local' directory
          when monitoring the corresponding testing file.
        - Verify that FIM deletes the 'diff' folder in the 'queue/diff/local' directory
          when removing the corresponding monitored folder.

    input_description: Different test cases are contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('deleted' events)

    tags:
        - diff
        - scheduled
        - time_travel
    '''
    fim_mode = get_configuration['metadata']['fim_mode']
    diff_dir = create_file_and_check_diff(FILE_NAME, path, fim_mode)
    shutil.rmtree(path, ignore_errors=True)
    wait_for_event(fim_mode)
    # Wait a second so diff path is deleted
    if 'scheduled' not in fim_mode:
        time.sleep(2)
    assert not os.path.exists(diff_dir), f'{diff_dir} exists'


def test_report_changes_after_restart(get_configuration, configure_environment,
                                      configure_local_internal_options_module, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon deletes the 'diff' folder created in the 'queue/diff/file'
                 directory when restarting that daemon, and the 'report_changes' option is disabled. For this
                 purpose, the test will monitor a directory and add a testing file inside it. Then, it will check
                 if a 'diff' file is created for the modified testing file. The folders in the 'queue/diff/file'
                 directory will be deleted after the 'wazuh-syscheckd' daemon restart but will be created again if
                 the 'report_changes' option is still active. To avoid this, the test will disable the 'report_changes'
                 option (backing the main configuration) before restarting the 'wazuh-syscheckd' daemon to ensure that
                 the directories will not be created again. Finally, the test will restore the backed configuration and
                 verify that the initial scan of FIM is made.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM adds the 'diff' file in the 'queue/diff/file' directory
          when monitoring the corresponding testing file.
        - Verify that FIM deletes the 'diff' folder in the 'queue/diff/file' directory
          when restarting the disabling the 'report_changes' option is disabled.

    input_description: Different test cases are contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)

    tags:
        - diff
        - scheduled
        - time_travel
    '''
    fim_mode = get_configuration['metadata']['fim_mode']

    # Create a file in the monitored path to force the creation of a report in diff
    diff_file_path = create_file_and_check_diff(FILE_NAME, testdir_reports, fim_mode)

    backup_conf = get_wazuh_conf()
    try:
        disable_report_changes(fim_mode)
        # Wait FIM to complete start and delete the diff_file
        time.sleep(5)
        assert not os.path.exists(diff_file_path), f'{diff_file_path} exists'
    finally:
        # Restore the original conf file so as not to interfere with other tests
        restart_wazuh_with_new_conf(backup_conf)
        detect_fim_scan(wazuh_log_monitor, fim_mode)
