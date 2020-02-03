# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
from datetime import timedelta

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = os.path.join(PREFIX, 'frequencydir')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

# Configuration with frequency values

frequencies = ['5', '3600', '10000']

p, m = generate_params(extra_params={'TEST_DIRECTORIES': directory_str},
                       apply_to_all=({'FREQUENCY': frequency} for frequency in frequencies),
                       modes=['realtime', 'whodata'])


configurations1 = load_wazuh_configurations(configurations_path, __name__,
                                            params=p,
                                            metadata=m)

configurations_path = os.path.join(test_data_path, 'wazuh_conf_default.yaml')

# Configuration with default frequency

conf_param, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str},
                                            modes=['realtime', 'whodata'])

configurations2 = load_wazuh_configurations(configurations_path, __name__,
                                            params=conf_param,
                                            metadata=conf_metadata)

# Merge both list of configurations into the final one to avoid skips and configuration issues
configurations = configurations1 + configurations2


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder, tags_to_apply', [
    (directory_str, {'ossec_conf'})
])
def test_frequency(folder, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                   wait_for_initial_scan):
    """ Checks if a non existing directory is monitored in realtime after the frequency time has passed

    Even with realtime monitoring, if we monitor a non existing directory and then we create it after restarting
    the service, syscheck won't detect anything from it until the scan restarts (using its frequency interval).

    :param folder: Directory that is being monitored

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    try:
        frequency = get_configuration['metadata']['frequency'] if 'frequency' in get_configuration['metadata'] \
            else 43200

        # Dont expect any event
        regular_file_cud(folder, wazuh_log_monitor, file_list=['regular'],
                         min_timeout=5, triggers_event=False)

        # Travel in time as many seconds as frequency is set to
        TimeMachine.travel_to_future(timedelta(seconds=int(frequency)))

        # Expect events now
        regular_file_cud(folder, wazuh_log_monitor, file_list=['regular'],
                         min_timeout=global_parameters.default_timeout, triggers_event=True)
    finally:
        # Remove directory since it is not included in fixture
        shutil.rmtree(directory_str, ignore_errors=True)
