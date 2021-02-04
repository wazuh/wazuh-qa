# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_event, callback_ignore, create_file,
                               REGULAR, generate_params, check_time_travel)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'),
                    os.path.join(PREFIX, 'testdir4'),
                    ]
dir1, dir2, dir3, dir4 = test_directories
dir_config = "{1}{0}{2}{0}{3}{0}{4}".format(", ", dir1, dir2, dir3, dir4)

multiples_paths = "{1}{0}{2}".format(os.pathsep, dir2, dir3)
environment_variables = [("TEST_IGN_ENV", multiples_paths)]

if sys.platform == 'win32':
    test_env = "%TEST_IGN_ENV%"
else:
    test_env = "$TEST_IGN_ENV"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_ignore.yaml')

conf_params = {'TEST_DIRECTORIES': dir_config, 'TEST_ENV_VARIABLES': test_env, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory, event_generated', [
    (dir1, True),
    (dir2, False),
    (dir3, False),
    (dir4, True),
])
def test_tag_ignore(directory, event_generated, get_configuration, configure_environment, put_env_variables,
                    restart_syscheckd, wait_for_fim_start):
    """
    Test environment variables are ignored
    """

    # Create text files
    filename = "test"
    create_file(REGULAR, directory, filename, content="")

    # Go ahead in time to let syscheck perform a new scan
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if event_generated:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(directory, filename), 'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                   callback=callback_ignore).result()
            if ignored_file == os.path.join(directory, filename):
                break
