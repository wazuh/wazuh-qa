# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=3)

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

file_list = []
for i in range(10000):
    file_list.append(f'regular_{i}')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

monitoring_modes = ['realtime', 'whodata']
conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str},
                                             modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.benchmark
@pytest.mark.parametrize('files, folder, tags_to_apply', [
    (file_list[0:10], testdir1, {'ossec_benchmark'}),
    (file_list[0:100], testdir1, {'ossec_benchmark'}),
    (file_list[0:1000], testdir1, {'ossec_benchmark'}),
    (file_list, testdir1, {'ossec_benchmark'})
])
def test_benchmark_regular_files(files, folder, tags_to_apply, get_configuration,
                                 configure_environment, restart_syscheckd,
                                 wait_for_initial_scan):
    """
    Check syscheckd detects a certain volume of file changes (add, modify, delete)

    Parameters
    ----------
    files: list
        List of regular files to be created.
    folder : str
        Monitored directory where files will be created.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    min_timeout = 30

    regular_file_cud(folder, wazuh_log_monitor, file_list=files,
                     min_timeout=min_timeout, triggers_event=True)
