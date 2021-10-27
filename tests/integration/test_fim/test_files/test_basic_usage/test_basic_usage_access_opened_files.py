# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import random
import string
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import delete_path_recursively
from wazuh_testing.tools.services import control_service


# Marks

pytestmark = [pytest.mark.tier(level=0)]

# Variables


directory_str = os.path.join(PREFIX, 'testdir1')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
file_path = os.path.join(directory_str, 'large_file')

# configurations


conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}

parameters, metadata = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def create_and_restore_large_file(request):
    os.mkdir(directory_str)

    file_size = 1024 * 1024 * 768   # 805 MB
    chunksize = 1024 * 768

    with open(file_path, "a") as f:
        while os.stat(file_path).st_size < file_size:
            f.write(random.choice(string.printable) * chunksize)
    yield

    delete_path_recursively(directory_str)
   

@pytest.fixture(scope='function')
def restart_syscheckd_function():
    """
    Restart syscheckd daemon.
    """
    control_service('restart', daemon='wazuh-syscheckd')             

# Tests


@pytest.mark.parametrize('operation, tags_to_apply', [
    ('delete', {'ossec_conf'}),
    ('rename', {'ossec_conf'})
])
def test_basic_usage_access_opened_files(operation, tags_to_apply, get_configuration, configure_environment,
                                         create_and_restore_large_file, restart_syscheckd_function, wait_for_fim_start_function):
    """
    Check that, when FIM is scanning a file, it can be modified by other processes.

    Parameters
    ----------
    operation : string
        Tells which operation has to be performed.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    with open(file_path, 'a') as f:
        f.write('a')

    check_time_travel(scheduled)

    if operation == 'rename':
        changed_path = os.path.join(directory_str, 'changed_name')

        try:
            os.rename(file_path, changed_path)
        except (OSError, IOError, PermissionError):
            pytest.fail('Could not rename file')
    elif operation == 'delete':
        try:
            os.remove(file_path)
        except (OSError, IOError, PermissionError):
            pytest.fail('Could not delete file')
