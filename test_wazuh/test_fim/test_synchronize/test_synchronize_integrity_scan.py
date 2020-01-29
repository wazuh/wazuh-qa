# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, DEFAULT_TIMEOUT
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories

file_list = []
for i in range(3000):
    file_list.append(f'regular_{i}')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': [testdir1, testdir2]},
                                             modes=['realtime', 'whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def extra_configuration_before_yield():
    # Create 5000 files before restarting Wazuh to make sure the integrity scan will not finish before testing
    for testdir in test_directories:
        for file in file_list:
            create_file(REGULAR, testdir, file, content='Sample content')


def callback_integrity_synchronization_check(line):
    if 'Initializing FIM Integrity Synchronization check' in line:
        return line
    return None


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'synchronize_events_conf'}
])
def test_events_while_integrity_scan(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """Check that events are being generated while a synchronization is being performed simultaneously.

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """
    folder = testdir1 if get_configuration['metadata']['fim_mode'] == 'realtime' else testdir2
    # Check the integrity scan has begun
    wazuh_log_monitor.start(timeout=15, callback=callback_integrity_synchronization_check)

    # Create a file and assert syscheckd detects it while doing the integrity scan
    file_name = 'file'
    create_file(REGULAR, folder, file_name, content='')
    sending_event = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()
    assert sending_event['data']['path'] == os.path.join(folder, file_name)
