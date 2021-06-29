# cat test_realtime_unsupported.py
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params, regular_file_cud, LOG_FILE_PATH, callback_num_inotify_watches, \
                              detect_initial_scan, CHECK_ALL, REQUIRED_ATTRIBUTES
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# variables


test_directories = [os.path.join(PREFIX, 'dir')]

directory_str = str(test_directories[0])
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_check_realtime.yaml')
testdir = test_directories
test_file = "testfile.txt"
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations


conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
parameters, metadata = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# fixtures


@pytest.fixture(scope='function', params=configurations)
def check_realtime_mode_failure():
    try:
        wazuh_log_monitor.start(timeout=60, callback=callback_num_inotify_watches,
                                error_message='Did not receive expected "Folders monitored with real-time engine..." \
                                event', update_position=False)
    except TimeoutError:
        detect_initial_scan(wazuh_log_monitor)


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder', testdir)
@pytest.mark.parametrize('file', [test_file])
# tests
def test_realtime_unsupported(folder, file, get_configuration, configure_environment, restart_syscheckd,
                              check_realtime_mode_failure):
    """ Check if the current OS platform falls to the scheduled mode when realtime isn't avaible.

    Params:
        folder (str): Name of the folder under PREFIX.
        file (str): Name of the file that will be created under folder.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        check_realtime_mode_failure (fixture): Try to catch the initial realtime monitorization event and if fails \
        then waits for the initial FIM scan event.
    """

    regular_file_cud(folder, wazuh_log_monitor, file_list=[file], time_travel=True, triggers_event=True,
                     event_mode="scheduled")
