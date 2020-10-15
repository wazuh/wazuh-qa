# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import pytest

from wazuh_testing.fim import REGULAR, check_time_travel, validate_event, create_file, modify_file, delete_file, \
    callback_detect_event


def multiple_dirs_test(mode=None, dir_list=None, file=None, scheduled=None, whodata=None,
                       log_monitor=None, timeout=1):
    """Perform a given action for every directory and validate all the events.

    Parameters
    ----------
    dir_list : list, optional
        List of created/monitored directories. Default `None`
    file : str, optional
        Name of the file to be created. Default `None`
    scheduled : str, optional
        Monitoring mode. Default `None`
    log_monitor : FileMonitor, optional
        File monitor. Default `None`
    timeout : int, optional
        Maximum timeout to raise a TimeoutError. Default `1`
    """

    if mode == "entries":
        n_results = len(dir_list)
    elif mode == "dirs":
        n_results = 64  # Maximum number of directories monitored in one line

    def perform_and_validate_events(func, kwargs):
        for directory in dir_list:
            args = [REGULAR, directory, file] if func.__name__ == 'create_file' else [directory, file]
            func(*args, **kwargs)
            if whodata:
                time.sleep(0.05)  # This sleep is to let whodata fetching all events

        check_time_travel(time_travel=scheduled)

        events = log_monitor.start(timeout=timeout,
                                   callback=callback_detect_event,
                                   accum_results=n_results,
                                   error_message='Did not receive expected "Sending FIM event: ..." event').result()
        time.sleep(1)

        for ev in events:
            validate_event(ev)

    try:
        perform_and_validate_events(create_file, {'content': ''})
        perform_and_validate_events(modify_file, {'new_content': 'New content'})
        perform_and_validate_events(delete_file, {})

    finally:
        for directory in dir_list:
            delete_file(directory, file)
