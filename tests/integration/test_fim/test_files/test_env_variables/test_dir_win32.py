# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, regular_file_cud
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir1', 'subdir')]
dir1, subdir1 = test_directories

environment_variables = [("TEST_ENV_VAR", dir1)]
test_env = "%TEST_ENV_VAR%"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_dir.yaml')

conf_params = {'TEST_ENV_VARIABLES': test_env, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory', [subdir1])
def test_tag_directories(directory, get_configuration, put_env_variables, configure_environment,
                         restart_syscheckd, wait_for_fim_start):
    """
    Test alerts are generated when monitor environment variables
    """
    regular_file_cud(directory, wazuh_log_monitor, file_list=["testing_env_variables"],
                     min_timeout=global_parameters.default_timeout,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
