# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from json import load
from shutil import rmtree
from time import sleep
import tempfile

import pytest
import wazuh_testing.tools.configuration as conf
from wazuh_testing import logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import check_daemon_status
from wazuh_testing.tools.services import control_service
from wazuh_testing.logcollector import delete_file_structure, get_data_sending_stats, get_next_stats, LOG_COLLECTOR_GLOBAL_TIMEOUT

# Marks
pytestmark = pytest.mark.tier(level=1)


# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
configurations_path = os.path.join(test_data_path, 'wazuh_configuration.yaml')


temp_dir = tempfile.gettempdir()

file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.txt'],
        'content': f'Content of testing_file\n'
    }
]

parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'), 'LOG_FORMAT': 'syslog'},
]

metadata = [
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test.txt')],
     'log_format': 'syslog'}
]


# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]
state_interval = [1]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.fixture(scope="module", params=state_interval)
def get_local_internal_options(request):
    """Get configurations from the module."""
    backup_options_lines = conf.get_wazuh_local_internal_options()
    if sys.platform == 'win32':
        conf.add_wazuh_local_internal_options({'\n windows.debug': '2'})
    else:
        conf.add_wazuh_local_internal_options({'\n logcollector.debug': '2'})
    conf.add_wazuh_local_internal_options({'logcollector.state_interval': request.param})
    control_service('restart')
    yield request.param
    conf.set_wazuh_local_internal_options(backup_options_lines)
    control_service('restart')


def test_options_state_interval_no_file(get_local_internal_options, get_files_list, create_file_structure_module,
                                        get_configuration, configure_environment, restart_logcollector):
    """Check if the monitorized file does not appear in logcollector.state when it is removed.

    Raises:
        AssertionError: If the elapsed time is different from the interval.
        TimeoutError: If the expected callback is not generated.
    """
    control_service('restart')
    interval = get_local_internal_options
    global_found = False
    interval_found = False
    for file in get_files_list:
        for name in file['filename']:
            log_path = os.path.join(file['folder_path'], name)
            with open(log_path, 'w') as file:
                file.write('Modifying the file')
            logcollector.wait_statistics_file(timeout=interval + 5)
            with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as json_file:
                data = load(json_file)
                global_files = data['global']['files']
                interval_files = data['interval']['files']
                for global_file in global_files:
                    if global_file['location'] == log_path:
                        global_found = True
                for interval_file in interval_files:
                    if interval_file['location'] == log_path:
                        interval_found = True
            os.remove(log_path)
            sleep(60)
            with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as next_json_file:
                data = load(next_json_file)
                with pytest.raises(KeyError):
                    global_files = data['global']['files']
                global_found = False
                with pytest.raises(KeyError):
                    interval_files = data['interval']['files']
                interval_found = False
    assert not global_found and not interval_found


