# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters
from wazuh_testing.tools.configuration import load_wazuh_configurations, PREFIX
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, WAZUH_PATH, generate_params

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'),
                    os.path.join(PREFIX, 'testdir4')
                    ]
dir1, dir2, dir3, dir4 = test_directories

# Check big environment variables ending with backslash
if sys.platform == 'win32':
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(10)] + [os.path.join(dir2, "test.txt"), os.path.join(dir3, "test.txt")]
    test_env = "%TEST_NODIFF_ENV%"
else:
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(100)] + [os.path.join(dir2, "test.txt"), os.path.join(dir3, "test.txt")]
    test_env = "$TEST_NODIFF_ENV"

multiple_env_var = os.pathsep.join(paths)
environment_variables = [("TEST_NODIFF_ENV", multiple_env_var)]

dir_config = ",".join(test_directories)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_nodiff.yaml')

conf_params = {'TEST_DIRECTORIES': dir_config, 'TEST_ENV_VARIABLES': test_env, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory, filename, hidden_content', [
    (dir1, "testing.txt", False),
    (dir2, "test.txt", True),
    (dir3, "test.txt", True),
    (dir4, "testing.txt", False),
])
def test_tag_nodiff(directory, filename, hidden_content, get_configuration, put_env_variables, configure_environment,
                    restart_syscheckd, wait_for_fim_start):
    """
    Test nodiff option works with environment variables

    Parameters
    ----------
    directory : str
        Directory where the file is being created.
    hidden_content : bool
        True if content must be truncated,, False otherwise.
    """

    files = {filename: b'Hello word!'}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for file in files:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')

            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')

            striped = directory.strip(os.sep) if sys.platform == 'darwin' else directory.strip(PREFIX)
            diff_file = os.path.join(diff_file, striped, file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if hidden_content:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'

    regular_file_cud(directory, wazuh_log_monitor, file_list=files,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
