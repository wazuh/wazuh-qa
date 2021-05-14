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

# marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]
matched_dirs = ['simple1', 'stars123']
test_subdirectories = matched_dirs + ['not_monitored_directory']
expresions = [os.path.join(test_folder, 'simple?'),
              os.path.join(test_folder, 'star*')]
expresion_str = ','.join(expresions)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_wildcards.yml')

# configurations

conf_params = {'TEST_WILDCARDS': expresion_str}
parameters, metadata = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def extra_configuration_before_yield():
    for sub_directory in test_subdirectories:

        if not os.path.exists(os.path.join(test_folder, sub_directory)):
            os.mkdir(os.path.join(test_folder, sub_directory))


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('parent_folder', [test_folder])
@pytest.mark.parametrize('subfolder_name', test_subdirectories)
@pytest.mark.parametrize('file_name', ['regular_1'])
@pytest.mark.parametrize('tags_to_apply', [{'ossec_conf_wildcards'}])
def test_basic_usage_wildcards(parent_folder, subfolder_name, file_name, tags_to_apply,
                               get_configuration, configure_environment, restart_syscheckd,
                               wait_for_fim_start):
    """Test the correct expansion of wildcards for monitored directories in syscheck

    The following wildcards expansions will be tried against the directory list:
        - test_folder/simple? will match simple?
        - test_folder/star* will match stars123
        - test_folder/*ple* will match simple1 and multiple_1
        - not_monitored_directory won't match any of the previous expressions

    For each subfolder there will be three different calls to regular_file_cud and
    for every subfolder the variable triggers_event will be set properly depending on the
    wildcards matching of the subfolder.

    Params:
        parent_folder (str): Name of the root folder.
        subfolder_name (str): Name of the subfolder under root folder.
        file_name (str): Name of the file that will be created under subfolder.
        tags_to_apply (str): Value holding the configuration used in the test.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.
    """
    if sys.platform == 'win32':
        if '?' in file_name or '*' in file_name:
            pytest.skip("Windows can't create files with wildcards.")
    check_apply_test(tags_to_apply, get_configuration['tags'])

    folder = os.path.join(parent_folder, subfolder_name)
    regular_file_cud(folder, wazuh_log_monitor, file_list=[file_name],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, triggers_event=subfolder_name in matched_dirs)
