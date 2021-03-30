# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import pytest
from wazuh_testing import global_parameters
import wazuh_testing.fim as fim
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Variables

monitored_folder = os.path.join(PREFIX, 'testdir')
test_directories = [monitored_folder]

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_check_inodes.yaml')
file_list = [f"file{i}" for i in range(10)]

# configurations

monitoring_modes = ['scheduled']

conf_params = {'TEST_DIRECTORIES': test_directories, 'MODULE_NAME': __name__}
params, metadata = fim.generate_params(extra_params=conf_params, modes=monitoring_modes,
                                       apply_to_all=({'CHECK_TYPE': check} for check in ['yes', 'no']))

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def restart_syscheck_function(get_configuration, request):
    """
    Reset ossec.log and start a new monitor.
    """
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(fim.LOG_FILE_PATH)
    file_monitor = FileMonitor(fim.LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon='wazuh-syscheckd')


@pytest.fixture(scope='function')
def wait_for_fim_start_function(get_configuration, request):
    """
    Wait for realtime start, whodata start or end of initial FIM scan.
    """
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    fim.detect_initial_scan(file_monitor)


# tests

@pytest.mark.parametrize('test_cases', [0, 1, 2])
def test_db_inode_check(test_cases, get_configuration, configure_environment, restart_syscheck_function,
                        wait_for_fim_start_function):
    """ Test to check for false positives due to possible inconsistencies with inodes in the database.
        Cases:
            - With check_mtime="no" and check_inode="no", no modification events should appear.
            - With check_mtime="yes" and check_inode="yes", modification events should have:
              "changed_attributes":["mtime","inode"]

    Args:
        test_added (boolean): variable to set whether the test will add one more or one less file.
        get_configuration (fixture): Function to access the configuration in use.
        configure_environment (fixture): Fixture to prepare the environment to pass the test
        restart_syscheck_function (fixture): Restart syscheck and truncate the log file with function scope.
        wait_for_fim_start_function (fixture): Wait until the log 'scan end' appear, with function scope.

    Raises:
        AttributeError: If an wrong or unexpected modified event appear
    """

    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    aux_file_list = file_list.copy()

    for file in aux_file_list:
        fim.create_file(fim.REGULAR, monitored_folder, file, content=file)

    # Time travel after creating the required files
    fim.check_time_travel(True, monitor=wazuh_log_monitor)

    shutil.rmtree(monitored_folder, ignore_errors=True)

    if test_cases == 0:
        # First case, adding a file ahead
        aux_file_list.insert(0, "file")
    elif test_cases == 1:
        # Second case, removing the first file
        aux_file_list.pop(0)
    elif test_cases == 2:
        # Third case, rotating files
        aux_file_list.pop(-1)
        aux_file_list.insert(0, "file9")

    for file in aux_file_list:
        fim.create_file(fim.REGULAR, monitored_folder, file, content=file)

    # Time travel after delete and create again a different number of files
    fim.check_time_travel(True, monitor=wazuh_log_monitor)

    if get_configuration['metadata']['check_type'] == 'yes':
        callback_test = fim.callback_detect_modified_event_with_inode_mtime
    else:
        callback_test = fim.callback_detect_modified_event

    shutil.rmtree(monitored_folder, ignore_errors=True)

    # Check unexpected events
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_test).result()
        if test_cases == 2:
            pytest.xfail('Xfailing due to false positive in special case, issue related: \
                          https://github.com/wazuh/wazuh/issues/7829')
        raise AttributeError(f'Unexpected event {event}')
