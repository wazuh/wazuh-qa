# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
import socket
import sys

from jq import jq

WAZUH_PATH = os.path.join('/', 'var', 'ossec')
ALERTS_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.json')
WAZUH_CONF_PATH = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')

FIFO = 'fifo'
SYSLINK = 'sys_link'
SOCKET = 'socket'
REGULAR = 'regular'

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


def load_fim_alerts(n_last=0):
    with open(ALERTS_FILE_PATH, 'r') as f:
        alerts = f.read()
    return list(filter(lambda x: x is not None, jq('.syscheck').transform(text=alerts, multiple_output=True)))[-n_last:]


def check_checkers(checkers, event):
    """ Checks if every checker is behaving correctly.
        If a checker value is "yes", it must appear in the log.
        Else, it must not appear in the log.

        Checkers keys must be the exact name of the attribute.
        Example: For check_sum="yes" you put "checksum":"yes" in checkers.

    :param checkers: Dict of checkers
    :type checkers: Dict
    :param event: Parsed JSON log.
    :type event: JSON
    :return: None
    """
    for check in checkers.items():
        if check[1] == "yes":
            assert(check[0] in event['data']['attributes'].keys())
        else:
            assert(check[0] not in event['data']['attributes'].keys())


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


def create_file(type, name, path, content=''):
    """ Creates a file in a given path.

    :param type: Defined constant that specifies the type. It can be: FIFO, SYSLINK, SOCKET or REGULAR
    :type type: Constant string
    :param name: File name
    :type name: String
    :param path: Path where the file will be created
    :type path: String
    :param content: Content of the file. Used for regular files.
    :type content: String or binary
    :return: None
    """
    getattr(sys.modules[__name__], f'_create_{type}')(path, name, content)


def _create_fifo(path, name, content):
    """ Creates a FIFO file.

    :param path: Path where the file will be created
    :type path: String
    :param name: File name
    :type name: String
    :param content: Content of the created file
    :type content: String or binary
    :return: None
    """
    fifo_path = os.path.join(path, name)
    try:
        os.mkfifo(fifo_path)
    except OSError:
        raise


def _create_sys_link(path, name, content):
    """ Creates a SysLink file.

    :param path: Path where the file will be created
    :type path: String
    :param name: File name
    :type name: String
    :param content: Content of the created file
    :type content: String or binary
    :return: None
    """
    syslink_path = os.path.join(path, name)
    try:
        os.symlink(syslink_path, syslink_path)
    except OSError:
        raise


def _create_socket(path, name, content):
    """ Creates a Socket file.

    :param path: Path where the file will be created
    :type path: String
    :param name: File name
    :type name: String
    :param content: Content of the created file
    :type content: String or binary
    :return: None
    """
    socket_path = os.path.join(path, name)
    try:
        os.unlink(socket_path)
    except OSError:
        if os.path.exists(socket_path):
            raise
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)


def _create_regular(path, name, content):
    """ Creates a Regular file.

    :param path: Path where the file will be created
    :type path: String
    :param name: File name
    :type name: String
    :param content: Content of the created file
    :type content: String or binary
    :return: None
    """
    regular_path = os.path.join(path, name)
    # Check if content is binary so it changes the mode
    isBinary = re.compile('^b\'.*\'$')
    if isBinary.match(str(content)):
        mode = 'wb'
    else:
        mode = 'w'
    with open(regular_path, mode) as f:
        f.write(content)


def change_internal_options(opt_path, pattern, value):
    """ Changes the value of a given parameter

    :param opt_path: File path
    :type opt_path: String
    :param pattern: Parameter to change
    :type pattern: String
    :param value: New value
    :type value: String
    """
    add_pattern = True
    with open(opt_path, "r") as sources:
        lines = sources.readlines()

    with open(opt_path, "w") as sources:
        for line in lines:
            sources.write(re.sub(f'{pattern}=[0-9]*', f'{pattern}={value}', line))
            if pattern in line:
                add_pattern = False

    if add_pattern:
        with open(opt_path, "a") as sources:
            sources.write(f'\n\n{pattern}={value}')


def callback_detect_end_scan(line):
    if 'File integrity monitoring scan ended.' in line:
        return line
    return None


def callback_detect_event(line):
    match = re.match(r'.*Sending event: (.+)$', line)
    if match:
        return json.loads(match.group(1))
    return None


def callback_audit_health_check(line):
    if 'Whodata health-check: Success.' in line:
        return True
    return None


def callback_audit_added_rule(line):
    match = re.match(r'.*Added audit rule for monitoring directory: \'(.+)\'', line)
    if match:
        return match.group(1)
    return None


def callback_audit_rules_manipulation(line):
    if 'Detected Audit rules manipulation' in line:
        return True
    return None


def callback_audit_connection(line):
    if '(6030): Audit: connected' in line:
        return True
    return None


def callback_audit_loaded_rule(line):
    match = re.match(r'.*Audit rule loaded: -w (.+) -p', line)
    if match:
        return match.group(1)
    return None


def callback_realtime_added_directory(line):
    match = re.match(r'.*Directory added for real time monitoring: \'(.+)\'', line)
    if match:
        return match.group(1)
    return None
