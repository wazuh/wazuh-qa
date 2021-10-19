# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import re
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params, regular_file_cud, LOG_FILE_PATH, callback_num_inotify_watches, \
                              detect_initial_scan, callback_ignore_realtime_flag, CHECK_ALL, REQUIRED_ATTRIBUTES
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks


pytestmark = [pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# variables

realtime_flag_timeout = 60
directory_str = os.path.join(PREFIX, 'dir')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_check_realtime.yaml')
test_file = 'testfile.txt'
test_directories = [directory_str]

# configurations


conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
parameters, metadata = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
local_internal_options = {'syscheck.debug': '2', 'monitord.rotate_log': '0'}
daemons_handler_configuration = {'daemons': ['wazuh-syscheckd']}

# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests


def test_realtime_unsupported(get_configuration, configure_environment, file_monitoring,
                              configure_local_internal_options_module, daemons_handler):
    """ Check if the current OS platform falls to the scheduled mode when realtime isn't avaible.

    Params:
        folder (str): Name of the folder under PREFIX.
        file (str): Name of the file that will be created under folder.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        check_realtime_mode_failure (fixture): Try to catch the initial realtime warning about ignoring the realtime  \
            flag event and then waits for the initial FIM scan event.
    """

    log_monitor.start(timeout=realtime_flag_timeout, callback=callback_ignore_realtime_flag,
                            error_message="Did not receive expected 'Ignoring flag for real time monitoring on  \
                            directory: ...' event", update_position=False)

    detect_initial_scan(log_monitor)

    regular_file_cud(directory_str, log_monitor, file_list=[test_file], time_travel=True, triggers_event=True,
                     event_mode="scheduled")
