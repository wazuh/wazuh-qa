# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from wazuh_testing.fim import REGULAR, check_time_travel, validate_event, create_file, modify_file, delete_file, \
    callback_detect_event
from wazuh_testing.tools import PREFIX

n_dirs = 100
test_directories = [os.path.join(PREFIX, f'testdir{i}') for i in range(n_dirs)]


def multiple_dirs_test(dir_list=None, file=None, scheduled=None, log_monitor=None, timeout=1):
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
    def perform_and_validate_events(func, kwargs):
        for directory in dir_list:
            args = [REGULAR, directory, file] if func.__name__ == 'create_file' else [directory, file]
            func(*args, **kwargs)

        check_time_travel(time_travel=scheduled)
        events = log_monitor.start(timeout=timeout,
                                   callback=callback_detect_event,
                                   accum_results=len(dir_list),
                                   error_message='Did not receive expected "Sending FIM event: ..." '
                                                 'event').result()

        for ev in events:
            validate_event(ev)

    try:
        perform_and_validate_events(create_file, {'content': ''})
        perform_and_validate_events(modify_file, {'new_content': 'New content'})
        perform_and_validate_events(delete_file, {})

    finally:
        for directory in dir_list:
            delete_file(directory, file)
