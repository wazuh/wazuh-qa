# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
from collections import Counter

import pytest
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, create_file, generate_params, callback_integrity_message, \
    callback_connection_message
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1), pytest.mark.agent]

# Variables
test_directories_no_delete = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories_no_delete)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_synchro.yaml')
testdir1 = os.path.join(PREFIX, 'testdir1')

# Configurations
conf_params = {'TEST_DIRECTORIES': directory_str,
               'MODULE_NAME': __name__}

eps_values = ['50', '10']
test_modes = ['realtime'] if sys.platform == 'linux' or sys.platform == 'win32' else ['scheduled']

p, m = generate_params(extra_params=conf_params, apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values),
                       modes=test_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def create_files(get_configuration):
    max_eps = get_configuration['metadata']['max_eps']
    mode = get_configuration['metadata']['fim_mode']
    for i in range(int(max_eps) * 5):
        create_file(REGULAR, testdir1, f'test{i}_{mode}_{max_eps}', content='')


@pytest.fixture(scope='function')
def delete_files():
    yield
    for test_dir in test_directories_no_delete:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_max_eps_on_start(get_configuration, create_files, configure_environment, restart_wazuh, delete_files):
    """
    Check that max_eps is respected when a big quantity of synchronization events are generated

    Before starting the service, a number of files is created thanks to fixture create_files.
    After that, syscheck is launched and starts generating synchronization events.
    """
    check_apply_test({'max_eps_synchronization'}, get_configuration['tags'])
    max_eps = int(get_configuration['metadata']['max_eps'])

    # Wait until the agent connects to the manager.
    wazuh_log_monitor.start(timeout=90,
                            callback=callback_connection_message,
                            error_message="Agent couldn't connect to server.").result()

    #  Find integrity start before attempting to read max_eps
    wazuh_log_monitor.start(timeout=30,
                            callback=callback_integrity_message,
                            error_message="Didn't receive integrity_check_global").result()

    n_results = max_eps * 5
    result = wazuh_log_monitor.start(timeout=120,
                                     accum_results=n_results,
                                     callback=callback_integrity_message,
                                     error_message=f'Received less results than expected ({n_results})').result()

    counter = Counter([date_time for date_time, _ in result])
    error_margin = (max_eps * 0.1)

    for _, n_occurrences in counter.items():
        assert n_occurrences <= round(
            max_eps + error_margin), f'Sent {n_occurrences} but a maximum of {max_eps} was set'
