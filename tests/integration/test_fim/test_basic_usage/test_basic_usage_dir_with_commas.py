# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, regular_file_cud
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'test,dir1'),
                    os.path.join(PREFIX, 'testdir2,')]
dir1, dir2 = test_directories

config_dirs = [os.path.join(PREFIX, 'test\\,dir1'),
               os.path.join(PREFIX, 'testdir2\\,')]
config_dirs = "{1}{0}{2}".format(", ", config_dirs[0], config_dirs[1])

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

conf_params = {'TEST_DIRECTORIES': config_dirs, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory', [
    dir1,
    dir2,
])
def test_directories_with_commas(directory, get_configuration, put_env_variables, configure_environment,
                                 restart_syscheckd, wait_for_fim_start):
    """
    Test alerts are generated when monitor environment variables
    """
    regular_file_cud(directory, wazuh_log_monitor, file_list=["testing_env_variables"],
                     min_timeout=global_parameters.default_timeout,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
