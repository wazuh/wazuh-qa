# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import tempfile
from time import sleep

import pytest
import wazuh_testing.tools.configuration as conf
from wazuh_testing import logcollector
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_configuration.yaml')
temp_dir = tempfile.gettempdir()

local_internal_options = {'logcollector.debug': '2'}

state_interval = [-2, 753951, 'dummy', 5, 10, 15]

file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.txt'],
        'content': f'Content of testing_file\n'
    }
]
parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'), 'LOG_FORMAT': 'syslog'}
]

metadata = [
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test.txt')],
     'log_format': 'syslog', 'file_type': 'single_file'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


@pytest.mark.parametrize('interval', state_interval)
def test_options_state_interval(interval, get_local_internal_options, get_files_list, create_file_structure_module,
                                get_configuration, configure_environment, restart_logcollector):
    """Check if logcollector is excluding specified files.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    backup_options_lines = conf.get_wazuh_local_internal_options()
    conf.add_wazuh_local_internal_options(get_local_internal_options)
    conf.add_wazuh_local_internal_options({'logcollector.state_interval': interval})
    if isinstance(interval, int):
        if interval not in range(0, 36001):
            with pytest.raises(ValueError):
                control_service('restart')
            log_callback = logcollector.callback_invalid_state_interval(interval)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message=f"Invalid definition for logcollector.state_interval: {interval}.")
        else:
            begin = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
            for file in get_files_list:
                for name in file['filename']:
                    with open(os.path.join(file['folder_path'], name), 'w') as file:
                        file.write('Modifying the file')
            sleep(interval)
            end = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
            elapsed = end - begin
            assert interval - 1 <= elapsed and elapsed <= interval + 2
    else:
        with pytest.raises(ValueError):
            control_service('restart')
        log_callback = logcollector.callback_invalid_state_interval(interval)
        wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                error_message=f"Invalid definition for logcollector.state_interval: {interval}.")

    conf.set_wazuh_local_internal_options(backup_options_lines)
