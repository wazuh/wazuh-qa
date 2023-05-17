# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json


from datetime import datetime
from wazuh_testing import logger
from wazuh_testing.modules.fim import CB_AGENT_CONNECT, CB_INTEGRITY_CONTROL_MESSAGE, CB_DETECT_FIM_EVENT


# Callback functions
def callback_connection_message(line):
    match = re.match(CB_AGENT_CONNECT, line)
    if match:
        return True


def callback_detect_integrity_control_event(line):
    match = re.match(CB_INTEGRITY_CONTROL_MESSAGE, line)
    if match:
        return json.loads(match.group(1))
    return None


def callback_integrity_message(line):
    if callback_detect_integrity_control_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))


def callback_detect_event(line):
    """
    Detect an 'event' type FIM log.
    
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
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


def callback_detect_file_added_event(line):
    """ Callback that detects if a line in a log is a file added event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'added':
            return json_event

    return None
