# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_registry_integrity_state_event
from wazuh_testing import global_parameters
from wazuh_testing.fim_module.fim_variables import MAX_EVENTS_VALUE, CB_REGISTRY_DBSYNC_NO_DATA
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator


def get_sync_msgs(tout, new_data=True):
    """Look for as many synchronization events as possible.

    This function will look for the synchronization messages until a Timeout is raised or 'max_events' is reached.

    Args:
        tout (int): Timeout that will be used to get the dbsync_no_data message.
        new_data (bool): Specifies if the test will wait the event `dbsync_no_data`.

    Returns:
        A list with all the events in json format.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    events = []
    if new_data:
        wazuh_log_monitor.start(timeout=tout,
                                callback=callback_generator(CB_REGISTRY_DBSYNC_NO_DATA),
                                error_message='Did not receive expected '
                                              '"db sync no data" event')
    for _ in range(0, MAX_EVENTS_VALUE):
        try:
            sync_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                 callback=callback_detect_registry_integrity_state_event,
                                                 accum_results=1,
                                                 error_message='Did not receive expected '
                                                               'Sending integrity control message"').result()
        except TimeoutError:
            break

        events.append(sync_event)

    return events


def find_value_in_event_list(key_path, value_name, event_list):
    """Function that looks for a key path and value_name in a list of json events.

    Args:
        path (str): Path of the registry key.
        value_name (str): Name of the value.
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
