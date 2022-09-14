# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import re
import json
from sys import platform
from wazuh_testing import LOG_FILE_PATH, logger
from wazuh_testing.fim_module import (CB_INODE_ENTRIES_PATH_COUNT, CB_FIM_ENTRIES_COUNT, CB_DETECT_FIM_EVENT)
from wazuh_testing.tools.monitoring import FileMonitor
from json import JSONDecodeError

file_monitor = FileMonitor(LOG_FILE_PATH)


def callback_detect_event(line):
    msg = CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event':
            return json_event
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_entries_path_count(line):
    if platform != 'win32':
        match = re.match(CB_INODE_ENTRIES_PATH_COUNT, line)
    else:
        match = re.match(CB_FIM_ENTRIES_COUNT, line)

    if match:
        if platform != 'win32':
            return match.group(1), match.group(2)
        else:
            return match.group(1), None


def callback_detect_end_scan(line):
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_end':
            return True
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_num_inotify_watches(line):
    match = re.match(r'.*Folders monitored with real-time engine: (\d+)', line)

    if match:
        return match.group(1)


def callback_real_time_whodata_started(line):
    if 'File integrity monitoring real-time Whodata engine started' in line:
        return True


def detect_initial_scan(file_monitor):
    """Detect initial scan when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_end_scan,
                       error_message='Did not receive expected "File integrity monitoring scan ended" event')


def detect_realtime_start(file_monitor):
    """Detect realtime engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_num_inotify_watches,
                       error_message='Did not receive expected "Folders monitored with real-time engine..." event')


def detect_whodata_start(file_monitor):
    """Detect whodata engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_real_time_whodata_started,
                       error_message='Did not receive expected'
                                     '"File integrity monitoring real-time Whodata engine started" event')
