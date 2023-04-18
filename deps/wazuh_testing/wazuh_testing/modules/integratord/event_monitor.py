'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''

from wazuh_testing import LOG_FILE_PATH, T_10
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback


# Callback string
CB_OPTIONS_FILE_DOES_NOT_EXISTENT = ".*OS_IntegratorD.*(JSON file for options  doesn't exist)"


# Functions
def check_integratord_event(file_monitor=None, callback='', error_message=None, update_position=True,
                            timeout=30, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if an event occurs
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=callback, error_message=error_message)


# Callback functions
def detect_integration_enabled(integration, file_monitor=None):
    """Detects integration has been enabled.

    Args:
        integration (str): The integratio that is being checked. Ex: Slack, Pagerduty and Shuffle
        file_monitor (FileMonitor): file log monitor to detect events
    """
    callback = fr".*(Enabling integration for: '{integration}')."
    check_integratord_event(file_monitor=file_monitor, callback=generate_monitoring_callback(callback),
                            error_message="Could not find the expected 'Enabling integration for...' event")


def detect_unable_to_run_integration(integration, file_monitor=None):
    """Detects is unable to be executed.

    Args:
        integration (str): The integration that is being checked. Ex: Slack, Pagerduty and Shuffle
        file_monitor (FileMonitor): file log monitor to detect events
    """
    callback = fr".*ERROR: Unable to run integration for ({integration}) -> integrations"
    check_integratord_event(file_monitor=file_monitor, callback=generate_monitoring_callback(callback),
                            error_message="Could not find the expected 'Unable to run integration for...' event")


def detect_options_json_file_does_not_exist(file_monitor=None):
    """Detects if JSON options file does not exist

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    check_integratord_event(file_monitor=file_monitor, timeout=T_10,
                            callback=generate_monitoring_callback(CB_OPTIONS_FILE_DOES_NOT_EXISTENT),
                            error_message="Could not find the expected 'JSON file doesn't exist...' event")


def detect_integration_response_code(response='200', file_monitor=None):
    """Detects the response code for the integration.

    Args:
        response (str): the response code for the integration. Defaults to 200
        file_monitor (FileMonitor): file log monitor to detect events
    """
    callback = fr'.*Response received.* \[({response})\].*'
    check_integratord_event(file_monitor=file_monitor, callback=generate_monitoring_callback(callback),
                            error_message="Could not find the expected 'Response received...' event")


def get_message_sent(integration, file_monitor):
    """Gets the message that is being sent to the integration.

    Args:
        integration (str): The integration that is being checked. Ex: Slack, Pagerduty and Shuffle
        file_monitor (FileMonitor): file log monitor to detect events
    Returns:
        string: Returns the message JSON string that was sent.
    """
    callback = fr'.*Sending message (.*) to {integration} server'

    result = file_monitor.start(timeout=T_10, update_position=True, accum_results=1,
                                callback=generate_monitoring_callback(callback),
                                error_message="Could not find the expected 'Sending message...' event").result()
    return result
