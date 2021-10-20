# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import random
import string

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, check_time_travel, detect_initial_scan
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service


# Marks


pytestmark = [pytest.mark.tier(level=0)]

# Variables


test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# configurations


conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def create_and_restore_large_file(request):
    if not os.path.exists(testdir1):
        os.mkdir(testdir1)

    file_size = 1024 * 1024 * 768   # 805 MB
    chunksize = 1024 * 768
    file_path = os.path.join(testdir1, 'large_file')
    changed_path = os.path.join(testdir1, 'changed_name')

    if os.path.exists(changed_path):
        os.rename(changed_path, file_path)
    elif not os.path.exists(file_path):
        with open(file_path, "a") as f:
            while os.stat(file_path).st_size < file_size:
                f.write(random.choice(string.printable) * chunksize)


@pytest.fixture()
def wait_for_initial_scan():
    """Fixture that waits for the initial scan, independently of the configured mode."""
    detect_initial_scan(wazuh_log_monitor)       


@pytest.fixture(scope='function')
def restart_syscheckd_basic(get_configuration, request):
    """
    Reset ossec.log and start a new monitor.
    """
    control_service('stop', daemon='wazuh-syscheckd')
    control_service('start', daemon='wazuh-syscheckd')             

# Tests


@pytest.mark.parametrize('operation, tags_to_apply', [
    ('delete', {'ossec_conf'}),
    ('rename', {'ossec_conf'})
])
def test_basic_usage_access_opened_files(operation, tags_to_apply, get_configuration, configure_environment,
                                         create_and_restore_large_file, restart_syscheckd_basic, wait_for_initial_scan):
    """
    Check that, when FIM is scanning a file, it can be modified by other processes.

    Parameters
    ----------
    operation : string
        Tells which operation has to be performed.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file_path = os.path.join(testdir1, 'large_file')

    with open(file_path, "a") as f:
        f.write('a')

    check_time_travel(scheduled)

    if operation == 'rename':
        changed_path = os.path.join(testdir1, 'changed_name')

        try:
            os.rename(file_path, changed_path)
        except (OSError, IOError, PermissionError):
            pytest.fail("Could not rename file")
    elif operation == 'delete':
        try:
            os.remove(file_path)
        except (OSError, IOError, PermissionError):
            pytest.fail("Could not delete file")
