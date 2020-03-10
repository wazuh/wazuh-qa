# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from collections import Counter

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, create_file, generate_params, callback_event_message, \
    check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = os.path.join(PREFIX, 'testdir1')

# Configurations
conf_params = {'TEST_DIRECTORIES': directory_str,
               'MODULE_NAME': __name__}

eps_values = ['50', '10']

p, m = generate_params(extra_params=conf_params, apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_max_eps(get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Check that max_eps is respected when a big quantity of syscheck events are generated.

    During the test, a big quantity of files are created and the max number of event occurrences per second is measured
    to ensure it never exceeds max_eps
    """
    check_apply_test({'max_eps'}, get_configuration['tags'])

    max_eps = int(get_configuration['metadata']['max_eps'])
    mode = get_configuration['metadata']['fim_mode']

    # Create files to read max_eps files with added events
    for i in range(int(max_eps) * 5):
        create_file(REGULAR, testdir1, f'test{i}_{mode}_{max_eps}', content='')

    check_time_travel(mode == "scheduled")
    n_results = max_eps * 4

    result = wazuh_log_monitor.start(timeout=(n_results/max_eps)*6,
                                     accum_results=n_results,
                                     callback=callback_event_message,
                                     error_message=f'Received less results than expected ({n_results})').result()

    counter = Counter([date_time for date_time, _ in result])
    error_margin = (max_eps * 0.1)

    for date_time, n_occurrences in counter.items():
        assert n_occurrences <= round(
            max_eps + error_margin), f'Sent {n_occurrences} but a maximum of {max_eps} was set'
