# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json

from wazuh_testing import T_60, T_10, T_20
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.modules import sca
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback


# Callbacks
def callback_scan_id_result(line):
    match = re.match(sca.CB_SCAN_RULE_RESULT, line)
    if match:
        return [match.group(1), match.group(2)]


def callback_detect_sca_scan_summary(line):
    match = re.match(sca.CB_SCA_SCAN_EVENT, line)
    if match:
        if json.loads(match.group(1))['type']=='summary':
            return json.loads(match.group(1))



# Event checkers
def check_sca_event(file_monitor=None, callback='', error_message=None, update_position=False,
                              timeout=T_60, accum_results=1,file_to_monitor=LOG_FILE_PATH):
    """Check if a sca event occurs

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
                       callback=generate_monitoring_callback(callback), error_message=error_message)


def check_sca_enabled(file_monitor=None):
    """Check if the sca module is enabled"""
    check_sca_event(callback=sca.CB_SCA_ENABLED, timeout=T_10, file_monitor=file_monitor)


def check_sca_disabled(file_monitor=None):
    """Check if the sca module is disabled"""
    check_sca_event(callback=sca.CB_SCA_DISABLED, timeout=T_10, file_monitor=file_monitor)


def check_sca_scan_started(file_monitor=None):
    """Check if the sca scan has started"""
    check_sca_event(callback=sca.CB_SCA_SCAN_STARTED, timeout=T_10, file_monitor=file_monitor)


def check_sca_scan_ended(file_monitor=None):
    """Check if the sca scan has ended"""
    check_sca_event(callback=sca.CB_SCA_SCAN_ENDED, timeout=T_10, file_monitor=file_monitor)


def check_scan_regex_engine(file_monitor=None):
    """Check the expected ammount of check results have been recieved"""
    file_monitor = FileMonitor(LOG_FILE_PATH) if file_monitor is None else file_monitor
    engine = file_monitor.start(callback=generate_monitoring_callback(sca.CB_SCA_OSREGEX_ENGINE), timeout=T_10,
                                 error_message=sca.ERR_MSG_REGEX_ENGINE, update_position=False).result()
    return engine


def get_sca_scan_rule_id_results(file_monitor=None, results_num=1):
    """Check the expected ammount of check results have been recieved"""
    file_monitor = FileMonitor(LOG_FILE_PATH) if file_monitor is None else file_monitor
    results = file_monitor.start(callback=callback_scan_id_result, timeout=T_20, accum_results=results_num,
                                 error_message=sca.ERR_MSG_ID_RESULTS).result()
    return results

def get_sca_scan_summary(file_monitor=None):
    """Get the scan summary event"""
    file_monitor = FileMonitor(LOG_FILE_PATH) if file_monitor is None else file_monitor
    results = file_monitor.start(callback=callback_detect_sca_scan_summary, timeout=T_20,
                                 error_message=sca.ERR_MSG_SCA_SUMMARY).result()
    return results
