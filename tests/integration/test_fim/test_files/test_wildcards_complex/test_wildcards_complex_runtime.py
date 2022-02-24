'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM monitors newly added directories
       that match with complex wildcards used in the configuration.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 1

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_wildcards_complex
'''
import os
import sys
import pytest
from wazuh_testing import global_parameters
from wazuh_testing import fim
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import recursive_directory_creation
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables
frequency_scan = 10
test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]

matched_dirs = [os.path.join('stardir', 'sub_test'), os.path.join('multiple_wildcards', 'sub_test'),
                os.path.join('directory_test', 'test_subdir1'), os.path.join('test_all', 'testdir'),
                os.path.join('test_all', 'testdir', 'all')]

no_match_dirs = ['random_directory']

wildcards = ','.join([os.path.join(test_folder, 'star*', 'sub*'), os.path.join(test_folder, 'mul*', '*test'),
                      os.path.join(test_folder, '*test*', '*dir?'), os.path.join(test_folder, 'test_all', '*'),
                      os.path.join(test_folder, 'test_all', '*', '*')])

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_wildcards_runtime.yml')
test_folders = matched_dirs + no_match_dirs

# Configurations

conf_params = {'TEST_WILDCARDS': wildcards, 'FREQUENCY': frequency_scan}
parameters, metadata = fim.generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# Fixtures

@pytest.fixture()
def wait_for_initial_scan():
    """Fixture that waits for the initial scan, independently of the configured mode."""
    fim.detect_initial_scan(wazuh_log_monitor)


@pytest.fixture()
def create_test_folders():
    """Fixture that creates all the folders specified in the `test_subdirectories` list"""
    for dir in test_folders:
        recursive_directory_creation(os.path.join(test_folder, dir))


@pytest.fixture()
def wait_for_wildcards_scan():
    """Fixture that waits until the end of the wildcards scan.
    The wildcards scan is triggered at the beginning of the FIM scan)."""
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + frequency_scan,
                            callback=fim.callback_detect_end_scan,
                            error_message='End of FIM scan not detected').result()


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh-qa#2174 - Needs Refactor")
@pytest.mark.parametrize('subfolder_name', test_folders)
@pytest.mark.parametrize('file_name', ['regular_1'])
@pytest.mark.parametrize('tags_to_apply', [{'ossec_conf_wildcards_runtime'}])
def test_wildcards_complex_runtime(subfolder_name, file_name, tags_to_apply,
                                   get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_initial_scan, create_test_folders, wait_for_wildcards_scan):
    '''
    description: Check if the number of directories to monitor grows when using complex wildcards to specify them.
                 For this purpose, the test will configure complex wildcards expressions and create an empty folder.
                 Once the FIM module has started, and the 'baseline' scan is completed, the test will create
                 folders that may match a configured expression, and it waits until the wildcards are expanded
                 again (in the next scan). Once the wildcards are reloaded, the test will create, modify and
                 delete files inside those folders. Finally, the test will wait for FIM events from a folder
                 only if it matches a configured expression.

    wazuh_min_version: 4.2.0

    parameters:
        - subfolder_name:
            type: str
            brief: Path to the subdirectory in the monitored folder.
        - file_name:
            type: str
            brief: Name of the testing file that will be created in the subfolder.
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
        - wait_for_initial_scan:
            type: fixture
            brief: Wait until the first FIM scan is completed.
        - create_test_folders:
            type: fixture
            brief: Create the testing folders that will match (or not) the configured glob expression.
        - wait_for_wildcards_scan:
            type: fixture
            brief: Wait until the end of wildcards scan event is triggered.

    assertions:
        - Verify that FIM events are generated from newly added directories that
          match a complex wildcard used in the configuration.

    input_description: A test case (ossec_conf_wildcards_runtime) is contained in external YAML file
                       (wazuh_conf_wildcards_runtime.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, it is combined with the testing directories
                       to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
        - who-data
    '''
    folder = os.path.join(test_folder, subfolder_name)
    if sys.platform == 'win32':
        if "?" in file_name or "*" in file_name:
            pytest.skip("Windows can't create files with wildcards.")

    if sys.platform == 'linux':
        # wait until the audit rules are reloaded
        whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
        fim.wait_for_audit(whodata, wazuh_log_monitor)
    check_apply_test(tags_to_apply, get_configuration['tags'])

    fim.regular_file_cud(folder, wazuh_log_monitor, file_list=[file_name],
                         time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                         min_timeout=global_parameters.default_timeout, triggers_event=subfolder_name in matched_dirs)
