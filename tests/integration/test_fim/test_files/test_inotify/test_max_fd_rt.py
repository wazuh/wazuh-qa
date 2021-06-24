# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import pytest
import wazuh_testing.fim as fim
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]
fd_rt_value = 2

created_dirs = [os.path.join(test_folder, 'test1'),
                os.path.join(test_folder, 'test2')]

extra_dirs = [os.path.join(test_folder, 'test3'),
              os.path.join(test_folder, 'test4')]
# Add all paths to the monitoring
dir_str = ','.join(created_dirs + extra_dirs)

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_max_fd.yaml')

# Configurations

conf_params = {'TEST_DIRECTORIES': dir_str}
parameters, metadata = fim.generate_params(extra_params=conf_params, modes=['realtime'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def extra_configuration_before_yield():
    for dir in created_dirs:
        if not os.path.exists(dir):
            os.mkdir(dir)
    fim.change_internal_options(param='syscheck.max_fd_win_rt', value=fd_rt_value)


def extra_configuration_after_yield():
    fim.change_internal_options(param='syscheck.max_fd_win_rt', value=256)


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('tags_to_apply', [{'test_max_fd_rt'}])
def test_max_fd_win_rt(tags_to_apply, get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """Check the correct behavior of the max_fd_win_rt internal option. Then test sets this option to two.
       The test will remove 2 monitored folders, then it will create those folders and check that events are
       triggered. After that, it will remove these folders.  Finally will create other 2 folders and will check that
       events are triggered.
       Args:
            tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
            get_configuration (fixture): Gets the current configuration of the test.
            configure_environment (fixture): Configure the environment for the execution of the test.
            restart_syscheckd (fixture): Restarts syscheck.
            wait_for_fim_start (fixture): Waits until the first FIM scan is completed.
       Raises:
            TimeoutError: If an expected event couldn't be captured.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    for dir in created_dirs:
        shutil.rmtree(dir)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_delete_watch,
                                error_message='Did not receive expected "Deleted realtime watch ..." event')

        os.mkdir(dir)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=fim.callback_realtime_added_directory,
                                error_message='Did not receive expected "Directory added for realtime ..." event')

        fim.regular_file_cud(dir, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, time_travel=False)
        shutil.rmtree(dir)

    for dir in extra_dirs:
        os.mkdir(dir)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=fim.callback_realtime_added_directory,
                                error_message='Did not receive expected "Directory added for realtime ..." event')
        fim.regular_file_cud(dir, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, time_travel=False)
