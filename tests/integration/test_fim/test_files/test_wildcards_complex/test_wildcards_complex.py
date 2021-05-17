# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables

test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]

matched_dirs = ['simple1', 'simple2', 'star12', 'stars123', 'multiple_1', 'multiplet']
matched_subdirs = ['sub_simple1', 'sub_simple2', 'substar', 'subdtar', '_submult', 'submult']
no_match_dirs = ['random_directory', 'not_monitored_directory', 'star12', 'stars123']

matched_subdirs = [os.path.join(parent, child) for parent, child in zip(matched_dirs, matched_subdirs)]
matched_dirs = [directory for directory in matched_dirs if directory not in no_match_dirs]
test_subdirectories = matched_dirs + matched_subdirs + no_match_dirs

wildcards = [os.path.join(test_folder, 'star*/sub*'),
             os.path.join(test_folder, 'mul*/*lt'),
             os.path.join(test_folder, '*ple*')]
wildcards = ','.join(wildcards)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_wildcards.yml')

# Configurations

conf_params = {'TEST_WILDCARDS': wildcards}
parameters, metadata = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def extra_configuration_before_yield():

    if not os.path.exists(test_folder):
        os.mkdir(test_folder)

    for no_match_dir in no_match_dirs:
        if not os.path.exists(os.path.join(test_folder, no_match_dir)):
            os.mkdir(os.path.join(test_folder, no_match_dir))

    for dir in matched_dirs:
        if not os.path.exists(os.path.join(test_folder, dir)):
            os.mkdir(os.path.join(test_folder, dir))

    for sub_directory in matched_subdirs:
        if not os.path.exists(os.path.join(test_folder, sub_directory)):
            os.mkdir(os.path.join(test_folder, sub_directory))


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test

@pytest.mark.parametrize('parent_folder', [test_folder])
@pytest.mark.parametrize('subfolder', test_subdirectories)
@pytest.mark.parametrize('file_name', ['regular_1', '*.*'])
@pytest.mark.parametrize('tags_to_apply', [{'ossec_conf_wildcards'}])
def test_wildcards_complex(parent_folder, subfolder, file_name, tags_to_apply,
                           get_configuration, configure_environment,
                           restart_syscheckd, wait_for_fim_start):
    """Test the correct expansion of complex wildcards for monitored directories in syscheck

    Params:
        parent_folder (str): Name of the root folder.
        subfolder (str): Name of the subfolder under root folder.
        file_name (str): Name of the file that will be created under subfolder.
        tags_to_apply (str): Value holding the configuration used in the test.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.
    """

    folder = os.path.join(parent_folder, subfolder)

    mult = 1 if sys.platform == 'win32' else 2

    if sys.platform == 'win32':
        if "?" in file_name or "*" in file_name:
            pytest.skip("Windows can't create files with wildcards.")

    check_apply_test(tags_to_apply, get_configuration['tags'])

    regular_file_cud(folder, wazuh_log_monitor, file_list=[file_name],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout * mult,
                     triggers_event=subfolder in matched_dirs or subfolder in matched_subdirs)
