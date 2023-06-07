# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json

from wazuh_testing import T_60, T_10, T_20
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.modules import sca
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback

# Callback Messages
CB_SCA_ENABLED = r".*sca.*INFO: (Module started.)"
CB_SCA_DISABLED = r".*sca.*INFO: (Module disabled). Exiting."
CB_SCA_SCAN_STARTED = r".*sca.*INFO: (Starting Security Configuration Assessment scan)."
CB_SCA_SCAN_ENDED = r".*sca.*INFO: Security Configuration Assessment scan finished. Duration: (\d+) seconds."
CB_SCA_OSREGEX_ENGINE = r".*sca.*DEBUG: SCA will use '(.*)' engine to check the rules."
CB_POLICY_EVALUATION_FINISHED = r".*sca.*INFO: Evaluation finished for policy '(.*)'."
CB_SCAN_DB_DUMP_FINISHED = r".*sca.*DEBUG: Finished dumping scan results to SCA DB for policy '(.*)'.*"
CB_SCAN_RULE_RESULT = r".*sca.*wm_sca_hash_integrity.*DEBUG: ID: (\d+); Result: '(.*)'"
CB_SCA_SCAN_EVENT = r".*sca_send_alert.*Sending event: (.*)"


# Error Messages
ERR_MSG_REGEX_ENGINE = "Did not receive the expected 'SCA will use '.*' engine to check the rules' event"
ERR_MSG_ID_RESULTS = 'Expected sca_has_integrity result events not found'
ERR_MSG_SCA_SUMMARY = 'Expected SCA Scan Summary type event not found.'


# Callback functions
def callback_scan_id_result(line):
    '''Callback that returns the ID an result of a SCA check
    Args:
        line (str): line string to check for match.
    '''
    match = re.match(CB_SCAN_RULE_RESULT, line)
    if match:
        return [match.group(1), match.group(2)]


def callback_detect_sca_scan_summary(line):
    '''Callback that return the json from a SCA summary event.
    Args:
        line (str): line string to check for match.
    '''
    match = re.match(CB_SCA_SCAN_EVENT, line)
    if match:
        if json.loads(match.group(1))['type'] == 'summary':
            return json.loads(match.group(1))


# Event check functions
def check_sca_event(file_monitor=None, callback='.*', error_message=None, update_position=False,
                    timeout=T_60, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if a sca event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
        file_to_monitor (str): Path of the file where to check for the expected events
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Expected event to found in {file_to_monitor}: {callback}" if error_message is None else \
                    error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=generate_monitoring_callback(callback), error_message=error_message)


def check_sca_enabled(file_monitor=None):
    """Check if the sca module is enabled
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
    """
    check_sca_event(callback=CB_SCA_ENABLED, timeout=T_10, file_monitor=file_monitor)


def check_sca_disabled(file_monitor=None):
    """Check if the sca module is disabled
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
    """
    check_sca_event(callback=CB_SCA_DISABLED, timeout=T_10, file_monitor=file_monitor)


def check_sca_scan_started(file_monitor=None):
    """Check if the sca scan has started
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
    """
    check_sca_event(callback=CB_SCA_SCAN_STARTED, timeout=T_10, file_monitor=file_monitor)


def check_sca_scan_ended(file_monitor=None):
    """Check if the sca scan has ended
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
    """
    check_sca_event(callback=CB_SCA_SCAN_ENDED, timeout=T_10, file_monitor=file_monitor)


def get_scan_regex_engine(file_monitor=None):
    """Check returns the regex engine used on a SCA scan.
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
    """
    file_monitor = FileMonitor(LOG_FILE_PATH) if file_monitor is None else file_monitor
    engine = file_monitor.start(callback=generate_monitoring_callback(CB_SCA_OSREGEX_ENGINE), timeout=T_10,
                                error_message=ERR_MSG_REGEX_ENGINE, update_position=False).result()
    return engine


def get_sca_scan_rule_id_results(file_monitor=None, results_num=1):
    """Check the expected ammount of check results have been recieved
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        results_num (int): Ammount of rule check results that should be recieved.
    """
    file_monitor = FileMonitor(LOG_FILE_PATH) if file_monitor is None else file_monitor
    results = file_monitor.start(callback=callback_scan_id_result, timeout=T_20, accum_results=results_num,
                                 error_message=ERR_MSG_ID_RESULTS).result()
    return results


def get_sca_scan_summary(file_monitor=None):
    """Get the scan summary event
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
    """
    file_monitor = FileMonitor(LOG_FILE_PATH) if file_monitor is None else file_monitor
    results = file_monitor.start(callback=callback_detect_sca_scan_summary, timeout=T_20,
                                 error_message=ERR_MSG_SCA_SUMMARY).result()
    return results
