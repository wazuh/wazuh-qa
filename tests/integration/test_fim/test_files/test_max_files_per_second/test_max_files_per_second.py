# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import wazuh_testing.fim as fim

from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1')]
max_files_per_second = 10
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
# Values for max_files_per_second option
values = [10, 0]
n_files_to_create = 50
# Configurations

conf_params = {'TEST_DIRECTORIES': test_directories[0]}
p, m = fim.generate_params(extra_params=conf_params, apply_to_all=({'MAX_FILES_PER_SEC': value} for value in values))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


def test_max_files_per_second(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """Check that FIM sleeps for one second when the option max_files_per_second is enabled

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.
    Raises:
        TimeoutError: If an expected event couldn't be captured.
    """
    # Create the files in an empty folder to check realtime and whodata.
    for i in range(n_files_to_create):
        fim.create_file(fim.REGULAR, test_directories[0], f'test_{i}', content='')

    extra_timeout = n_files_to_create / max_files_per_second

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    fim.check_time_travel(scheduled)
    try:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + extra_timeout,
                                callback=fim.callback_detect_max_files_per_second)
    except TimeoutError as e:
        if get_configuration['metadata']['max_files_per_sec'] == 0:
            pass
        else:
            raise e
