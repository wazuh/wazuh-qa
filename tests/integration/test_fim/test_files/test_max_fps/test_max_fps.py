# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, callback_detect_max_fps, \
     check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1')]
MAX_FPS = 10
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
fps_values = [10, 0]
# Configurations

conf_params = {'TEST_DIRECTORIES': test_directories[0]
               }
p, m = generate_params(extra_params=conf_params, apply_to_all=({'MAX_FPS': fps_value} for fps_value in fps_values),
                       modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def extra_configuration_before_yield():
    for i in range(50):
        create_file(REGULAR, test_directories[0], f'test_{i}', content='')

# Tests


def test_max_fps(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check that FIM sleeps for one second when the option max_fps is enabled
    """
    check_time_travel(True, monitor=wazuh_log_monitor)
    try:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                callback=callback_detect_max_fps)
    except TimeoutError:
        if get_configuration['metadata']['max_fps'] == 0:
            pass
        else:
            raise TimeoutError
