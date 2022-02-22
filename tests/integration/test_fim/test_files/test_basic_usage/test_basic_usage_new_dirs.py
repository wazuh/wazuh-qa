'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM events are generated
       after the next scheduled scan using the 'scheduled' monitoring mode.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 0

modules:
    - fim

components:
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_basic_usage
'''
import os
import shutil
import sys
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import detect_initial_scan
from wazuh_testing.fim import generate_params, regular_file_cud, callback_non_existing_monitored_dir
from wazuh_testing.tools import PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

test_directories = []
directory_str = os.path.join(PREFIX, 'testdir1')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path,
                                   'wazuh_conf_new_dirs.yaml' if sys.platform != 'win32'
                                   else 'wazuh_conf_new_dirs_win32.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations
windows_audit_interval = 1
conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__,
               'WINDOWS_AUDIT_INTERVAL': str(windows_audit_interval)}
p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """Make sure to delete any existing directory with the same name before performing the test"""
    shutil.rmtree(directory_str, ignore_errors=True)


def extra_configuration_after_yield():
    """Make sure to delete the directory after performing the test"""
    shutil.rmtree(directory_str, ignore_errors=True)


# Tests
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
def test_new_directory(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'CUD' (creation, update, and delete) events after
                 the next scheduled scan. For this purpose, the test will create a monitored folder and several
                 testing files inside it. Then, it will perform different operations over the testing files and
                 verify that no events are generated before the next scheduled scan. Finally, the test
                 will perform operations on another set of testing files and wait to the next scheduled scan for
                 the expected FIM events to be generated.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that FIM events are generated after the next scheduled scan using the 'scheduled' monitoring mode.

    input_description: A test case (ossec_conf) is contained in external YAML file
                       (wazuh_conf_new_dirs.yaml or wazuh_conf_new_dirs_win32.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if sys.platform != 'win32':
        detect_initial_scan(wazuh_log_monitor)

        # Create the monitored directory with files and check that events are not raised
        regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file1', 'file2', 'file3'],
                         min_timeout=global_parameters.default_timeout, triggers_event=False)

        detect_initial_scan(wazuh_log_monitor)
    else:
        detect_initial_scan(wazuh_log_monitor)

        # Wait for syscheck to realize the directories don't exist
        wazuh_log_monitor.start(timeout=10, callback=callback_non_existing_monitored_dir,
                                error_message='Monitoring discarded message not found')
        os.makedirs(directory_str, exist_ok=True, mode=0o777)
        time.sleep(windows_audit_interval + 0.5)

    # Assert that events of new CUD actions are raised after next scheduled scan
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file4', 'file5', 'file6'],
                     min_timeout=40, triggers_event=True)
