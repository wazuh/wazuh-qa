# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json

from sys import platform
from datetime import datetime

from wazuh_testing import logger
from wazuh_testing.modules.fim import (CB_AGENT_CONNECT, CB_INTEGRITY_CONTROL_MESSAGE, CB_INODE_ENTRIES_PATH_COUNT,
                                       CB_FIM_ENTRIES_COUNT, CB_DETECT_FIM_EVENT)


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