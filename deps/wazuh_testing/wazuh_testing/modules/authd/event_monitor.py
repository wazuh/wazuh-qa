'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import re

from wazuh_testing import T_30
from wazuh_testing.modules.authd import AUTHD_PREFIX
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor


def make_authd_callback(pattern, prefix=AUTHD_PREFIX):
    """Create a callback function from a text pattern.

    It already contains the authd prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as prefix before the pattern.

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_empty_pass_error = make_authd_callback("ERROR: Empty password provided.")
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_authd_event(file_monitor=None, callback='', error_message=None, update_position=True,
                      prefix=AUTHD_PREFIX, timeout=T_30, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if an authd event occurs.
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if not error_message \
        else error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_authd_callback(callback, prefix), error_message=error_message)
