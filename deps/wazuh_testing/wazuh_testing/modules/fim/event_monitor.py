# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json

from datetime import datetime
from wazuh_testing import logger
from wazuh_testing.tools.monitoring import generate_monitoring_callback
from wazuh_testing.modules import fim


# Callbacks
def callback_detect_event(line):
    """
    Detect an 'event' type FIM log.
    """
    msg = fim.CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event':
            return json_event
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_end_scan(line):
    """ Callback that detects if a line in a log is an end of scheduled scan event
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    msg = fim.CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_end':
            return True
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_scan_start(line):
    """ Callback that detects if a line in a log is the start of a scheduled scan or initial scan.
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    msg = fim.CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_start':
            return True
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_connection_message(line):
    match = re.match(fim.CB_AGENT_CONNECT, line)
    if match:
        return True


def callback_detect_integrity_control_event(line):
    match = re.match(fim.CB_INTEGRITY_CONTROL_MESSAGE, line)
    if match:
        return json.loads(match.group(1))
    return None


def callback_integrity_message(line):
    if callback_detect_integrity_control_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))


def callback_detect_registry_integrity_clear_event(line):
    event = callback_detect_integrity_control_event(line)
    if event and event['component'] == 'fim_registry' and event['type'] == 'integrity_clear':
        return True
    return None


def callback_disk_quota_limit_reached(line):
    match = re.match(fim.CB_FILE_EXCEEDS_DISK_QUOTA, line)

    if match:
        return match.group(2)


# Event checkers
def detect_initial_scan(file_monitor):
    """Detect initial scan when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_end_scan,
                       error_message=fim.ERR_MSG_SCHEDULED_SCAN_ENDED)


def detect_initial_scan_start(file_monitor):
    """Detect initial scan start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_scan_start,
                       error_message=fim.ERR_MSG_SCHEDULED_SCAN_STARTED)


def detect_realtime_start(file_monitor):
    """Detect realtime engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=generate_monitoring_callback(fim.CB_FOLDERS_MONITORED_REALTIME),
                       error_message=fim.ERR_MSG_FOLDERS_MONITORED_REALTIME)


def detect_whodata_start(file_monitor):
    """Detect whodata engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=generate_monitoring_callback(fim.CB_REALTIME_WHODATA_ENGINE_STARTED),
                       error_message=fim.ERR_MSG_WHODATA_ENGINE_EVENT)


def detect_windows_sacl_configured(file_monitor, file):
    
    callback = fr".*win_whodata.*The SACL of '({file})' will be configured"
    
    file_monitor.start(timeout=60, callback=generate_monitoring_callback(callback),
                       error_message=fim.ERR_MSG_SACL_CONFIGURED_EVENT)


def detect_windows_whodata_mode_change(file_monitor, file):
    
    callback = fr".*set_whodata_mode_changes.*The '({file})' directory starts to be monitored in real-time mode."
    
    file_monitor.start(timeout=60, callback=generate_monitoring_callback(callback),
                       error_message=fim.ERR_MSG_WHDATA_REALTIME_MODE_CHANGE_EVENT)