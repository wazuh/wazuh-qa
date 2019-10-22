# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
import shutil
import socket
import sys
import time
from collections import Counter
from datetime import timedelta
from stat import ST_ATIME, ST_MTIME

from jq import jq
from jsonschema import validate

from wazuh_testing.tools import TimeMachine

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

WAZUH_PATH = os.path.join('/', 'var', 'ossec')
ALERTS_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.json')
WAZUH_CONF_PATH = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')

FIFO = 'fifo'
SYSLINK = 'sys_link'
SOCKET = 'socket'
REGULAR = 'regular'

_last_log_line = 0

def validate_mitre_event(event):
    """ Checks if a Mitre event is properly formatted.

    :param event: dict representing an event generated by rule enhanced by MITRE

    :return: None
    """
    with open(os.path.join(_data_path, 'mitre_event.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=event)

def callback_detect_mitre_event(line):
    """ Callback to detect Mitre event when restarting Wazuh

    :param line: string to be compared with alerts in ossec.log
    :return: JSON object on success or None on fail
    """
    match = re.match(r'.*Sending mitre event: (.+)$', line)
    if match:
        return json.loads(match.group(1))
    return None

def callback_detect_end_sca_scan(line):
    if 'Security Configuration Assessment scan finished.' in line:
        return line
    return None

def detect_initial_sca_scan(file_monitor):
    """ Detect end SCA scan when restarting Wazuh

    :param file_monitor: Wazuh log monitor to detect syscheck events
    :type file_monitor: FileMonitor
    :return: None
    """
    file_monitor.start(timeout=20, callback=callback_detect_end_sca_scan)