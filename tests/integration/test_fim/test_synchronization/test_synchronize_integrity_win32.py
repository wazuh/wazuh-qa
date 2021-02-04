# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import timedelta
import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, create_registry, generate_params, \
        create_file, modify_registry_value, REGULAR, callback_detect_event, callback_real_time_whodata_started, \
        KEY_WOW64_64KEY, registry_parser, REG_SZ
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

from wazuh_testing.tools.time import TimeMachine

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables
key = "HKEY_LOCAL_MACHINE"
subkey = "SOFTWARE\\test_key"

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
test_regs = [os.path.join(key, subkey)]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_integrity_scan_win32.yaml')
testdir1, testdir2 = test_directories
conf_params = {'TEST_DIRECTORIES': test_directories,
               'TEST_REGS': os.path.join(key, subkey)}

file_list = []
subkey_list = []
for i in range(3000):
    file_list.append(f'regular_{i}')
    subkey_list.append(f'subkey_{i}')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params=conf_params,
                                             modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def extra_configuration_before_yield():
    # Create 3000 files before restarting Wazuh to make sure the integrity scan will not finish before testing
    for testdir in test_directories:
        for file, reg in zip(file_list, subkey_list):
            create_file(REGULAR, testdir, file, content='Sample content')
            create_registry(registry_parser[key], os.path.join(key, 'SOFTWARE', reg), KEY_WOW64_64KEY)


def callback_integrity_synchronization_check(line):
    if 'Initializing FIM Integrity Synchronization check' in line:
        return line
    return None


def callback_integrity_or_whodata(line):
    if callback_integrity_synchronization_check(line):
        return 1
    elif callback_real_time_whodata_started(line):
        return 2


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'synchronize_events_conf'}
])
def test_events_while_integrity_scan(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """Check that events are being generated while a synchronization is being performed simultaneously.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    folder = testdir1 if get_configuration['metadata']['fim_mode'] == 'realtime' else testdir2
    key_h = create_registry(registry_parser[key], subkey, KEY_WOW64_64KEY)

    # Wait for whodata to start and the synchronization check. Since they are different threads, we cannot expect
    # them to come in order every time
    if get_configuration['metadata']['fim_mode'] == 'whodata':
        value_1 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                          callback=callback_integrity_or_whodata,
                                          error_message='Did not receive expected "File integrity monitoring '
                                                        'real-time Whodata engine started" or "Initializing '
                                                        'FIM Integrity Synchronization check"').result()

        value_2 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                          callback=callback_integrity_or_whodata,
                                          error_message='Did not receive expected "File integrity monitoring '
                                                        'real-time Whodata engine started" or "Initializing FIM '
                                                        'Integrity Synchronization check"').result()
        assert value_1 != value_2, "callback_integrity_or_whodata detected the same message twice"

    else:
        # Check the integrity scan has begun
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 3,
                                callback=callback_integrity_synchronization_check,
                                error_message='Did not receive expected '
                                              '"Initializing FIM Integrity Synchronization check" event')

    # Create a file and a registry value. Assert syscheckd detects it while doing the integrity scan
    file_name = 'file'
    create_file(REGULAR, folder, file_name, content='')
    modify_registry_value(key_h, "test_value", REG_SZ, 'added')

    sending_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
    assert sending_event['data']['path'] == os.path.join(folder, file_name)

    TimeMachine.travel_to_future(timedelta(hours=13))
    sending_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
    assert sending_event['data']['path'] == os.path.join(key, subkey)
    assert sending_event['data']['arch'] == '[x64]'
