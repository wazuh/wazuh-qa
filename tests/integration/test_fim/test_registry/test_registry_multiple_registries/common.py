# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh_testing.fim import create_registry, registry_parser, check_time_travel, modify_registry, delete_registry, \
    callback_detect_event, validate_registry_key_event, KEY_WOW64_32KEY, modify_registry_value, delete_registry_value, \
    validate_registry_value_event, callback_value_event, REG_SZ, RegCloseKey


def multiple_keys_and_entries_keys(num_entries, subkeys, log_monitor, root_key, timeout=10):
    """
    Perform a given action for every registry key and validate all the events. Performs registry key actions.

    Parameters
    ----------
    num_entries: int
        Number of events to find.
    subkeys: list
        List with all the subkeys to modify.
    log_monitor : FileMonitor
        File monitor.
    root_key: str
        Name of the root registry key (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER).
    timeout: int, optional
        Maximum timeout to raise a TimeoutError. Default `10`
    """
    def perform_and_validate_events(func):
        for reg in subkeys:
            func(registry_parser[root_key], os.path.join(reg, 'test_key'), KEY_WOW64_32KEY)

        check_time_travel(True, monitor=log_monitor)

        events = log_monitor.start(timeout=timeout,
                                   callback=callback_detect_event,
                                   accum_results=num_entries,
                                   error_message='Did not receive expected "Sending FIM event: ..." event').result()

        for ev in events:
            validate_registry_key_event(ev)

    perform_and_validate_events(create_registry)
    perform_and_validate_events(modify_registry)
    perform_and_validate_events(delete_registry)


def multiple_keys_and_entries_values(num_entries, subkeys, log_monitor, root_key, timeout=10):
    """
    Perform a given action for every registry key and validate all the events. Performs registry value actions.

    Parameters
    ----------
    num_entries: int
        Number of events to find.
    subkeys: list
        List with all the subkeys to modify.
    log_monitor : FileMonitor
        File monitor.
    root_key: str
        Name of the root registry key (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER).
    timeout: int, optional
        Maximum timeout to raise a TimeoutError. Default `10`
    """
    def perform_and_validate_events(func, content='added', is_delete=False):
        for reg in subkeys:
            key_handle = create_registry(registry_parser[root_key], reg, KEY_WOW64_32KEY)
            if not is_delete:
                func(key_handle, 'test_value', REG_SZ, content)
            else:
                func(key_handle, 'test_value')
            RegCloseKey(key_handle)

        check_time_travel(True, monitor=log_monitor)

        events = log_monitor.start(timeout=timeout,
                                   callback=callback_value_event,
                                   accum_results=num_entries,
                                   error_message='Did not receive expected "Sending FIM event: ..." event').result()

        for ev in events:
            validate_registry_value_event(ev)

    perform_and_validate_events(modify_registry_value)  # Create
    perform_and_validate_events(modify_registry_value, content='modified')  # Modify
    perform_and_validate_events(delete_registry_value, is_delete=True)  # Delete
