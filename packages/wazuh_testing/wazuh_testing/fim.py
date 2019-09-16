# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re

from jq import jq

WAZUH_PATH = os.path.join('/', 'var', 'ossec')
ALERTS_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.json')
WAZUH_CONF_PATH = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')

_last_log_line = 0


def check_path(value):
    return re.match(r'^(?:\/[^\/]+)*$', value)


def check_integer_formatted_string(value):
    return re.match(r'^\d+$', value)


def check_md5(value):
    return re.match(r'^[a-f0-9]{32}$', value)


def check_sha1(value):
    return re.match(r'^[0-9a-f]{5,40}$', value)


def check_sha256(value):
    return re.match(r'^[a-f0-9]{64}$', value)


def check_datetime(value):
    return re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}$', value)


def check_string(value):
    return isinstance(value, str)


def check_integer(value):
    return isinstance(value, int)


def check_event(value):
    return value in ('added', 'modified', 'deleted')


FIELDS = {'path': check_path,
          'size_after': check_integer_formatted_string,
          'perm_after': check_integer_formatted_string,
          'uid_after': check_integer_formatted_string,
          'gid_after': check_integer_formatted_string,
          'md5_after': check_md5,
          'sha1_after': check_sha1,
          'sha256_after': check_sha256,
          'uname_after': check_string,
          'gname_after': check_string,
          'mtime_after': check_datetime,
          'inode_after': check_integer,
          'event': check_event}


def check_fim_alert(alert, exclude_fields=None):
    """Checks a FIM alert is properly formatted"""
    exclude_fields = [] if exclude_fields is None else exclude_fields

    for field, checker in FIELDS.items():
        if field not in exclude_fields:
            assert(field in alert)
            assert(checker(alert[field]))


def load_fim_alerts(n_last=0):
    with open(ALERTS_FILE_PATH, 'r') as f:
        alerts = f.read()
    return list(filter(lambda x: x is not None, jq('.syscheck').transform(text=alerts, multiple_output=True)))[-n_last:]


def is_fim_scan_ended():
    message = 'File integrity monitoring scan ended.'
    line_number = 0
    with open(LOG_FILE_PATH, 'r') as f:
        for line in f:
            line_number += 1
            if line_number > _last_log_line:  # Ignore if has not reached from_line
                if message in line:
                    globals()['_last_log_line'] = line_number
                    return line_number
    return -1


def callback_detect_end_scan(line):
    if 'File integrity monitoring scan ended.' in line:
        print(f"Detecto fin de scan en línea: {line}")
        return line
    return None


def callback_detect_event(line):
    match = re.match(r'.*Sending event: (.+)$', line)
    if match:
        print(f"Detecto evento en línea: {line}")
        print(f"Evento detectado: {json.loads(match.group(1))}")
        return json.loads(match.group(1))
    return None
