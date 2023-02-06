# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

import wazuh_testing as fw
from wazuh_testing.modules import api
from wazuh_testing.api import API_LOGIN_ENDPOINT
from wazuh_testing.tools.monitoring import FileMonitor


def make_api_callback(pattern, prefix=api.API_PREFIX):
    """Create a callback function from a text pattern.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as prefix before the pattern.

    Returns:
        lambda: function that returns if there's a match in the file
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_api_event(file_monitor=None, callback='', error_message=None, update_position=True, timeout=fw.T_20,
                    prefix=api.API_PREFIX, accum_results=1, file_to_monitor=fw.API_LOG_FILE_PATH):
    """Check if an API event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in the file
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in the file
        timeout (int): timeout to check the event in the file
        prefix (str): log pattern regex
        accum_results (int): Accumulation of matches.
        file_to_monitor (str): File to be monitored.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_api_callback(callback, prefix), error_message=error_message)


def check_api_start_log(log_monitor=None, timeout=fw.T_30, host='0.0.0.0', port='55000',
                        file_to_monitor=fw.API_LOG_FILE_PATH):
    """Check if the start event is in the log file.

    Args:
        log_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (int): timeout to check the event in the log file
        host (str): IP of the host
        port (str): port of the host
        file_to_monitor (str): file that will be monitored
    """
    check_api_event(log_monitor, callback=fr".*Listening on {host}:{port}.+", timeout=timeout,
                    file_to_monitor=file_to_monitor)


def check_api_debug_log(log_monitor=None, timeout=fw.T_5, file_to_monitor=fw.API_LOG_FILE_PATH):
    """Check if a debug event is in the log file.

    Args:
        log_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (int): timeout to check the event in the log file
        file_to_monitor (str): file that will be monitored
    """
    check_api_event(log_monitor, callback=r".*DEBUG:.*", timeout=timeout, file_to_monitor=file_to_monitor)


def check_api_login_request(log_monitor=None, timeout=fw.T_5, user='wazuh', host='127.0.0.1',
                            file_to_monitor=fw.API_LOG_FILE_PATH):
    """Check if the login request event is in the log file.

    Args:
        log_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (int): timeout to check the event in the log file
        user (str): user used to make the request
        host (str): IP of the host
        file_to_monitor (str): file that will be monitored
    """
    check_api_event(log_monitor, callback=fr'.*INFO.*{user}.*{host}.*{API_LOGIN_ENDPOINT}.*', timeout=timeout,
                    file_to_monitor=file_to_monitor)


def check_api_timeout_error(log_monitor=None, timeout=fw.T_10, file_to_monitor=fw.API_LOG_FILE_PATH):
    """Check if the timeout error event is in the log file.

    Args:
        log_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (int): timeout to check the event in the log file
        file_to_monitor (str): file that will be monitored
    """
    check_api_event(log_monitor, callback=fr".*ERROR.*{api.TIMEOUT_ERROR_LOG}.*", timeout=timeout,
                    file_to_monitor=file_to_monitor)
