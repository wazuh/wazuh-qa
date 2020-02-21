# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from collections import Counter

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, create_file, generate_params, callback_syscheck_message
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# configurations
conf_params = {'TEST_DIRECTORIES': directory_str,
               'MODULE_NAME': __name__}

eps_values = ['10', '50', '100', '200', '500']

p, m = generate_params(extra_params=conf_params, apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def extra_configuration_before_yield():
    # Create 1500 files before starting syscheck, not all will be expected
    for i in range(1500):
        create_file(REGULAR, testdir1, f'test{i}', content='')


def test_max_eps_on_start(get_configuration, configure_environment, restart_syscheckd):
    """
    Check that max_eps is respected when a big quatity of events are generated

    Before starting the service, a great number of files is created thanks to function `extra_configuration_before_yield`.
    After that, syscheck is launched and starts generating as much events as files created.
    """
    check_apply_test({'max_eps'}, get_configuration['tags'])

    result = wazuh_log_monitor.start(timeout=150,
                                     accum_results=1000,
                                     callback=callback_syscheck_message,
                                     error_message='Did not receive expected any integrity event').result()

    max_eps = int(get_configuration['metadata']['max_eps'])
    counter = Counter([date_time for date_time, _ in result])
    error_margin = (max_eps * 0.1)

    for date_time, n_occurrences in counter.items():
        assert n_occurrences <= round(
            max_eps + error_margin), f'Sent {n_occurrences} but a maximum of {max_eps} was set'
