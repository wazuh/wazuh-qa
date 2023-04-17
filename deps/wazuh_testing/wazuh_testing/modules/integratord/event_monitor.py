'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor


# Callback string
CB_OPTIONS_NON_EXISTENT = ".*OS_IntegratorD.*JSON file  doesn't exist"


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
    callback = fr".*Enabling integration for: '{integration}'."
    check_integratord_event(file_monitor=file_monitor, callback=callback)


def detect_unable_to_run_integration(integration, file_monitor=None):
    """Detects is unable to be executed.

    Args:
        integration (str): The integration that is being checked. Ex: Slack, Pagerduty and Shuffle
        file_monitor (FileMonitor): file log monitor to detect events
    """
    callback = fr".*ERROR: Unable to run integration for {integration} -> integrations"
    check_integratord_event(file_monitor=file_monitor, callback=callback)


def detect_options_json_file_does_not_exist(file_monitor=None):
    """Detects if JSON options file does not exist

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    check_integratord_event(file_monitor=file_monitor, callback=CB_OPTIONS_NON_EXISTENT)