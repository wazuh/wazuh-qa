'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import re

from wazuh_testing import T_5, T_20, T_30
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules import integratord


def make_integratord_callback(pattern, prefix=integratord.INTEGRATORD_PREFIX):
    '''Create a callback function from a text pattern.

    It already contains the vulnerability-detector prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as prefix before the pattern.

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_bionic_update_started = make_vuln_callback("Starting Ubuntu Bionic database update")
    '''
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_integratord_event(file_monitor=None, callback='', error_message=None, update_position=True,
                            timeout=T_30, accum_results=1, file_to_monitor=LOG_FILE_PATH,
                            prefix=integratord.INTEGRATORD_PREFIX):
    '''Check if an event occurs
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
        prefix (str): log pattern regex
    '''
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_integratord_callback(callback, prefix), error_message=error_message)


def check_integratord_thread_ready(file_monitor=None, timeout=T_5):
    '''Check if a local requests thread ready in the logs.

    Args:
        log_monitor (FileMonitor): Log monitor.
        timeout (int): Event timeout.
    '''
    check_integratord_event(file_monitor=file_monitor, timeout=timeout,
                            callback=integratord.CB_INTEGRATORD_THREAD_IS_READY,
                            error_message='Did not receive the expected "Local requests thread ready"')


def check_file_inode_changed(file_monitor=None, timeout=T_20):
    '''Check for Alert file inode changed in the logs.

    Args:
        log_monitor (FileMonitor): Log monitor.
        timeout (int): Event timeout.
    '''
    check_integratord_event(file_monitor=file_monitor, timeout=timeout, callback=integratord.CB_INODE_CHANGED,
                            error_message='Did not receive the expected "...Alert file inode changed..." event')


def check_alert_processing(file_monitor=None, timeout=T_20):
    '''Check for Processing alert message in the logs.

    Args:
        log_monitor (FileMonitor): Log monitor.
        timeout (int): Event timeout.
    '''
    check_integratord_event(file_monitor=file_monitor, timeout=timeout, callback=integratord.CB_PROCESSING_ALERT,
                            error_message='Did not receive the expected Slack alert in alerts.json')


def check_third_party_response(file_monitor=None, timeout=T_20):
    '''Check for response message in the logs.

    Args:
        log_monitor (FileMonitor): Log monitor.
        timeout (int): Event timeout.
    '''
    check_integratord_event(file_monitor=file_monitor, timeout=timeout, callback=integratord.CB_THIRD_PARTY_RESPONSE,
                            error_message='Could not send the alert to slack')


def check_invalid_alert_read(file_monitor=None, timeout=T_20, callback='', error_message=None):
    '''Check for invalid alert read message in the logs.

    Args:
        log_monitor (FileMonitor): Log monitor.
        timeout (int): Event timeout.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
    '''
    check_integratord_event(file_monitor=file_monitor, timeout=timeout, callback=callback, error_message=error_message)


def check_file_warning(file_monitor=None, timeout=T_20):
    '''Check for information of file in the logs.

    Args:
        log_monitor (FileMonitor): Log monitor.
        timeout (int): Event timeout.
    '''
    check_integratord_event(file_monitor=file_monitor, timeout=timeout,
                            callback=integratord.CB_ALERT_JSON_FILE_NOT_FOUND,
                            error_message='Did not receive the expected "...Could not retrieve information/open file"')
