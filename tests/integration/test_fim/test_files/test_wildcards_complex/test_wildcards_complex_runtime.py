# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
from wazuh_testing import global_parameters
from wazuh_testing import fim
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
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
        split_path = os.path.split(dir)
        parent_folder = os.path.join(test_folder, split_path[0])
        if not os.path.exists(parent_folder):
            os.mkdir(os.path.join(parent_folder))
        if not os.path.exists(os.path.join(parent_folder, split_path[1])):
            os.mkdir(os.path.join(parent_folder, split_path[1]))


@pytest.fixture()
def wait_for_wildcards_scan():
    """Fixture that waits until the end of the wildcards scan.
    The wildcards scan is triggered at the beggining of the FIM scan)."""
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + frequency_scan,
                            callback=fim.callback_detect_end_scan,
                            error_message='End of FIM scan not detected').result()


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test

@pytest.mark.parametrize('subfolder_name', test_folders)
@pytest.mark.parametrize('file_name', ['regular_1'])
@pytest.mark.parametrize('tags_to_apply', [{'ossec_conf_wildcards_runtime'}])
def test_wildcards_complex_runtime(subfolder_name, file_name, tags_to_apply,
                                   get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_initial_scan, create_test_folders, wait_for_wildcards_scan):
    """Test the correct expansion of complex wildcards in runtime for monitored directories in syscheck.
        The test will monitor an empty folder and once the baseline scan is completed, it will create folders that may
        match one of the monitored expresions and will check that the events are triggered (in case that a folder
        doesn't match the configured expresion, the test will check that no events are triggered in those folders.)
    Params:
        subfolder (str): Name of the subfolder under root folder.
        file_name (str): Name of the file that will be created under subfolder.
        tags_to_apply (str): Value holding the configuration used in the test.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_initial_scan (fixture): Waits until the first FIM scan is completed.
        create_test_folders (fixture): Creates the folders that will match (or not) the configured glob expresion.
        wait_for_wildcards_scan (fixture): Waits until the end of wildcards scan event is triggered.
    """

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
