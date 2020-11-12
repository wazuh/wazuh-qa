# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters

from test_fim.test_multiple_dirs.common import multiple_dirs_test
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_warn_max_dir_monitored, \
                               detect_initial_scan, detect_realtime_start, detect_whodata_start
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import PREFIX

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

n_dirs = 70
test_directories = [os.path.join(PREFIX, f'testdir{i}') for i in range(n_dirs)]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'multiple_dirs.yaml')
expected_discarded = ','.join([os.path.join(PREFIX, f'testdir{i}') for i in range(64, n_dirs)])

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# functions


def wait_for_event():
    # Wait until event is detected
    discarded = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_warn_max_dir_monitored,
                                        error_message='Did not receive expected "Maximum number of directories to be '
                                                      'monitored in the same tag reached" event').result()
    return discarded

# tests


@pytest.mark.parametrize('dir_list, tags_to_apply', [
    (test_directories, {'multiple_dirs'})
])
def test_multiple_dirs(dir_list, tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check if syscheck can detect every event when adding, modifying and deleting a file within multiple monitored
    directories.
    Check that the maximum number of monitored directories are processed correctly, generating a warning,
    and discarding the excess.

    These directories will be added in one single entry like so:
        <directories>testdir0, testdir1, ..., testdirn</directories>

    Parameters
    ----------
    dir_list : list
        List with all the directories to be monitored.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    discarded = wait_for_event()
    assert discarded == expected_discarded, f'Directories discarded expected to be: {discarded}'

    if get_configuration['metadata']['fim_mode'] == 'realtime':
        detect_realtime_start(wazuh_log_monitor)
    elif get_configuration['metadata']['fim_mode'] == 'whodata':
        detect_whodata_start(wazuh_log_monitor)
    else:   # scheduled
        detect_initial_scan(wazuh_log_monitor)

    file = 'regular'

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'

    try:
        multiple_dirs_test(mode="dirs", dir_list=dir_list, file=file, scheduled=scheduled, whodata=whodata,
                           log_monitor=wazuh_log_monitor, timeout=2 * global_parameters.default_timeout)
    except TimeoutError as e:
        if whodata:
            pytest.xfail(reason='Xfailed due to issue: https://github.com/wazuh/wazuh/issues/4731')
        else:
            raise e
