# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import socket

from wazuh_testing.tools import ARCHIVES_LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, REMOTED_DETECTOR_PREFIX


def callback_detect_remoted_started(port, protocol, connection_type="secure"):
    """Creates a callback to detect if remoted was correctly started

    wazuh-remoted logs if it has correctly started for each connection type, the port and
    the protocol in the ossec.log

    Args:
        port (int): port configured for wazuh-remoted.
        protocol (str): protocol configured for wazuh-remoted. It can be UDP, TCP or both options at the same time.
        connection_type (str): it can be secure or syslog.

    Returns:
        callable: callback to detect this event
    """
    msg = fr"Started \(pid: \d+\). Listening on port {port}\/{protocol} \({connection_type}\)."

    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_detect_syslog_event(message):
    """Creates a callback to detect the syslog messages in the archives.log

    Args:
        message (str): syslog message sent through the socket

    Returns:
        callable: callback to detect this event
    """
    expr = fr".*->\d+\.\d+\.\d+\.\d+\s{message}"
    return make_callback(pattern=expr, prefix=None)


def send_syslog_message(message, port, protocol, manager_address="127.0.0.1"):
    """This function sends the ping message to the manager

    This message is the first of many between the manager and the agents. It is used to check if both of them are ready
    to send and receive other messages

    Args:
        message (str): string to send as a syslog event.
        protocol (str): it can be UDP or TCP.
        port (int): port where the manager has bound the remoted port
        manager_address (str): address of the manager.

    Raises:
        ConnectionRefusedError: if there's a problem while sending messages to the manager
    """
    if protocol == "UDP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if not message.endswith("\n"):
        message += "\n"

    sock.connect((manager_address, port))
    sock.send(message.encode())
    sock.close()


def create_archives_log_monitor():
    """Creates a FileMonitor for the archives.log file

    Returns:
        FileMonitor: object to monitor the archives.log
    """
    # Reset ossec.log and start a new monitor
    truncate_file(ARCHIVES_LOG_FILE_PATH)
    wazuh_archives_log_monitor = FileMonitor(ARCHIVES_LOG_FILE_PATH)

    return wazuh_archives_log_monitor


def detect_archives_log_event(archives_monitor, callback, error_message, update_position=True, timeout=5):
    archives_monitor.start(timeout=timeout, update_position=update_position, callback=callback,
                           error_message=error_message)


def check_syslog_event(wazuh_archives_log_monitor, message, port, protocol):
    """Check if a syslog event is properly receive by the manager.

    Args:
        wazuh_archives_log_monitor (FileMonitor): FileMonitor object to monitor the archives.log.
        message (str): Message sent for syslog that must appear in the archives.log.
        protocol (str): it can be UDP or TCP.
        port (int): port where the manager has bound the remoted port
    """
    send_syslog_message(message, port, protocol)
    detect_archives_log_event(archives_monitor=wazuh_archives_log_monitor,
                              callback=callback_detect_syslog_event(message),
                              error_message="Syslog message wasn't received or took too much time.")
