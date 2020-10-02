# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.fim import (LOG_FILE_PATH, generate_params, callback_detect_event,
                               REGULAR, create_file, delete_file)
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2')
                    ]
dir1, dir2 = test_directories

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_whodata_prevails_over_realtime.yaml')

conf_params = {'TEST_DIR1': dir1, 'TEST_DIR2': dir2, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['whodata'])

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
def test_whodata_prevails_over_realtime(directory, get_configuration, put_env_variables, configure_environment,
                                        restart_syscheckd, wait_for_fim_start):
    """
    Test alerts are generated when monitor environment variables
    """
    filename = "testfile"

    create_file(REGULAR, directory, filename, content="")
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event).result()

    if (event['data']['mode'] != 'whodata' and event['data']['type'] != 'added' and
            os.path.join(directory, filename) in event['data']['path']):
        raise AssertionError('Event not found')

    delete_file(directory, filename)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event).result()

    if (event['data']['mode'] != 'whodata' and event['data']['type'] != 'deleted' and
            os.path.join(directory, filename) in event['data']['path']):
        raise AssertionError('Event not found')
