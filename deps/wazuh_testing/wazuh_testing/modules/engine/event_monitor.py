# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from wazuh_testing.modules import engine
from wazuh_testing.tools.monitoring import FileMonitor


def make_engine_callback(pattern, prefix=engine.ENGINE_PREFIX):
    """Create a callback function from a text pattern.

    It already contains the wazuh-engine prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as prefix before the pattern.

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_api_connection = make_vuln_callback("Engine API endpoint: ... [{API_SOCKET_PATH}]")
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_engine_event_output(file_monitor=None, event='', error_message=None, update_position=True,
                              timeout=engine.T_1, accum_results=1, prefix=engine.ENGINE_PREFIX,
                              file_to_monitor=engine.ENGINE_ALERTS_PATH):
    """Check if a vulnerability event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        event (str): event to check within the engine alerts
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the engine alerts
        prefix (str): event pattern regex
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {event}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_engine_callback(event, prefix), error_message=error_message)
