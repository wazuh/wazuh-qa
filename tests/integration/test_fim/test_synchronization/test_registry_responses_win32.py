'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM synchronizes the
       registry DB when a modification is performed while the agent is down and decodes
       the synchronization events properly.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os
import pytest
import wazuh_testing.fim as fim
from wazuh_testing import global_parameters
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables
key = "HKEY_LOCAL_MACHINE"
monitored_key = "SOFTWARE\\random_key"

sync_interval = 20
max_events = 20

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_responses_win32.yaml')
conf_params = {'WINDOWS_REGISTRY': os.path.join(key, monitored_key), 'SYNC_INTERVAL': sync_interval}
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = fim.generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def get_sync_msgs(tout, new_data=True):
    """Look for as many synchronization events as possible.
    This function will look for the synchronization messages until a Timeout is raised or 'max_events' is reached.
    Params:
        tout (int): Timeout that will be used to get the dbsync_no_data message.
        new_data (bool): Specifies if the test will wait the event `dbsync_no_data`
    Returns:
        A list with all the events in json format.
    """
    events = []
    if new_data:
        wazuh_log_monitor.start(timeout=tout,
                                callback=fim.callback_dbsync_no_data,
                                error_message='Did not receive expected '
                                              '"db sync no data" event')
    for _ in range(0, max_events):
        try:
            sync_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                 callback=fim.callback_detect_registry_integrity_state_event,
                                                 accum_results=1,
                                                 error_message='Did not receive expected '
                                                               'Sending integrity control message"').result()
        except TimeoutError:
            break

        events.append(sync_event)

    return events


def find_value_in_event_list(key_path, value_name, event_list):
    """Function that looks for a key path and value_name in a list of json events.
    Params:
        path (str): Path of the registry key.
        value_name (str): Name of the value
        event_list (list): List containing the events in JSON format.
    Returns:
        The event that matches the specified path. None if no event was found.
    """
    for event in event_list:
        if 'value_name' not in event.keys():
            continue

        if event['path'] == key_path and event['value_name'] == value_name:
            return event

    return None


def extra_configuration_after_yield():
    """Remove the registry key when the test ends"""
    fim.delete_registry(fim.registry_parser[key], monitored_key, fim.KEY_WOW64_64KEY)


@pytest.fixture(scope='function', params=configurations)
def create_key(request):
    """Fixture that create the test key And then delete the key and truncate the file. The aim of this
       fixture is to avoid false positives if the manager still has the test  key
       in it's DB.
    """
    control_service('stop')
    fim.create_registry(fim.registry_parser[key], monitored_key, fim.KEY_WOW64_64KEY)

    yield
    fim.delete_registry(fim.registry_parser[key], monitored_key, fim.KEY_WOW64_64KEY)
    control_service('stop')
    truncate_file(fim.LOG_FILE_PATH)
    file_monitor = FileMonitor(fim.LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start')

    # wait until the sync is done.
    wazuh_log_monitor.start(timeout=sync_interval + global_parameters.default_timeout,
                            callback=fim.callback_detect_registry_integrity_clear_event,
                            error_message='Did not receive expected "integrity clear" event')


# tests


@pytest.mark.parametrize('key_name', [':subkey1', 'subkey2:', ':subkey3:'])
@pytest.mark.parametrize('value_name', [':value1', 'value2:', ':value3:'])
def test_registry_sync_after_restart(key_name, value_name, get_configuration, configure_environment,
                                     create_key):
    '''
    description: Check if the 'wazuh-syscheckd' daemon synchronizes the registry DB when a modification
                 is performed while the agent is down. For this purpose, the test will monitor a key and
                 wait for the synchronization. Then it will stop the agent, make key/value operations inside
                 the monitored key, and start the agent again. Finally, it will wait for the synchronization
                 and verify that FIM sync events generated include the key and value paths for
                 the modifications made.

    wazuh_min_version: 4.2.0

    parameters:
        - key_name:
            type: str
            brief: Name of the subkey that will be created in the test.
        - value_name:
            type: str
            brief: Name of the value that will be created in the test.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_key:
            type: fixture
            brief: Create the test key.

    assertions:
        - Verify that FIM sync events generated include the monitored value path and
          its parent key path of the changes made while the agent was stopped.

    input_description: A test case (registry_sync_responses) is contained in external YAML file
                       (wazuh_conf_registry_responses_win32.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon. That is combined with the
                       testing registry key to be monitored defined in this module.

    expected_output:
        - r'.*#!-fim_registry dbsync no_data (.+)'
        - r'.*Sending integrity control message'

    tags:
        - scheduled
        - time_travel
    '''
    key_path = os.path.join(monitored_key, key_name)
    value_path = os.path.join(key, key_path, value_name)

    # stops syscheckd
    key_handle = fim.create_registry(fim.registry_parser[key], key_path, fim.KEY_WOW64_64KEY)

    fim.modify_registry_value(key_handle, value_name, fim.REG_SZ, 'This is a test with syscheckd down.')
    control_service('start')

    events = get_sync_msgs(sync_interval)

    assert find_value_in_event_list(
               os.path.join(key, key_path), value_name, events) is not None, f"No sync event was found for {value_path}"
