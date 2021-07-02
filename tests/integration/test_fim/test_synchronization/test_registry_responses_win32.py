# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
subkey = "SOFTWARE\\random_key"

sync_interval = 20
max_events = 20

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_responses_win32.yaml')
conf_params = {'WINDOWS_REGISTRY': os.path.join(key, subkey), 'SYNC_INTERVAL': sync_interval}
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


def find_path_in_event_list(path, event_list):
    """Function that looks for a key path in a list of json events.
    Params:
        path (str): Path of the registry key.
        event_list (list): List containing the events in JSON format.
    Returns:
        The event that matches the specified path. None if no event was found.
    """
    for event in event_list:
        if event['path'] == path:
            return event
    return None


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
    fim.delete_registry(fim.registry_parser[key], subkey, fim.KEY_WOW64_64KEY)


@pytest.fixture(scope='function', params=configurations)
def remove_key_and_restart(request):
    """Fixture that removes the test key and restart the agent. The aim of this
       fixture is to avoid false positives if the manager still has the test  key
       in it's DB.
    """
    fim.delete_registry(fim.registry_parser[key], subkey, fim.KEY_WOW64_64KEY)
    control_service('stop')
    truncate_file(fim.LOG_FILE_PATH)
    file_monitor = FileMonitor(fim.LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start')

    # wait until the sync is done.
    wazuh_log_monitor.start(timeout=sync_interval + 15, callback=fim.callback_detect_registry_integrity_clear_event,
                            error_message='Did not receive expected "integrity clear" event')


# tests

@pytest.mark.parametrize('tags_to_apply', [{'registry_sync_responses'}])
@pytest.mark.parametrize('key_name', [':subkey1', 'subkey2:', ':subkey3:'])
@pytest.mark.parametrize('value_name', [':value1', 'value2:', ':value3:'])
def test_registry_sync_after_restart(key_name, value_name, tags_to_apply, get_configuration, configure_environment,
                                     remove_key_and_restart):
    """
    Test to check that FIM synchronizes the registry DB when a modification is performed while the agent is down.

    Params:
        key_name (str): Name of the subkey that will be created in the test.
        value_name (str): Name of the value that will be created in the test. If
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.
    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If a path or value are not in the sync event.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    key_path = os.path.join(subkey, key_name)
    value_path = os.path.join(key, key_path, value_name)

    # stops syscheckd
    control_service('stop')
    fim.create_registry(fim.registry_parser[key], subkey, fim.KEY_WOW64_64KEY)
    key_handle = fim.create_registry(fim.registry_parser[key], key_path, fim.KEY_WOW64_64KEY)

    fim.modify_registry_value(key_handle, value_name, fim.REG_SZ, 'This is a test with syscheckd down.')
    control_service('start')

    events = get_sync_msgs(sync_interval)

    assert find_value_in_event_list(
               os.path.join(key, key_path), value_name, events) is not None, f"No sync event was found for {value_path}"
