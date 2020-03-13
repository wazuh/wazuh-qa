# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import base64
import random
import re
import string
import struct

from cryptography.fernet import Fernet

CLUSTER_DATA_HEADER_SIZE = 20
CLUSTER_HEADER_FORMAT = '!2I{}s'.format(12)
FERNET_KEY = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
_my_fernet = Fernet(base64.b64encode(FERNET_KEY.encode()))


def callback_detect_master_serving(line):
    match = re.match(r'.*Serving on \(', line)
    if match:
        return line


def callback_detect_worker_connected(line):
    match = re.match(r'.*Sucessfully connected to master', line)
    if match:
        return line


def callback_clusterd_keypoll(item):
    return process_clusterd_message(item, command=b'run_keypoll ')


def detect_initial_worker_connected(file_monitor):
    """
    Detect worker node is connected to master after restarting clusterd.

    Parameters
    ----------
    file_monitor : FileMonitor
        Wazuh log monitor to cluster.log

    Raises
    ------
    TimeoutError
        If no worker connection is detected before 'timeout' seconds
    """
    file_monitor.start(timeout=5, callback=callback_detect_worker_connected)


def detect_initial_master_serving(file_monitor):
    """
    Detect master node is TCP serving on localhost:PORT after restarting clusterd.

    Parameters
    ----------
    file_monitor : FileMonitor
        Wazuh log monitor to cluster.log

    Raises
    ------
    TimeoutError
        If no master serving message is detected before 'timeout' seconds
    """
    file_monitor.start(timeout=5, callback=callback_detect_master_serving)


def cluster_msg_build(command: bytes, counter: int, data: bytes, encrypt=True) -> bytes:
    """
    Build a message using cluster protocol.

    Parameters
    ----------
    command : bytes
        command to send
    counter : int
        message id
    data : bytes
        data to send
    encrypt : bool
        whether to use fernet encryption or not

    Returns
    -------
    bytes
        built message
    """
    cmd_len = len(command)
    if cmd_len > 12:
        raise Exception("Length of command '{}' exceeds limit ({}/{}).".format(command, cmd_len, 12))

    encrypted_data = _my_fernet.encrypt(data) if encrypt else data
    out_msg = bytearray(20 + len(encrypted_data))
    header_format = '!2I{}s'.format(12)

    # Add - to command until it reaches cmd length
    command = command + b' ' + b'-' * (12 - cmd_len - 1)

    out_msg[:20] = struct.pack(header_format, counter, len(encrypted_data), command)
    out_msg[20:20 + len(encrypted_data)] = encrypted_data

    return bytes(out_msg[:20 + len(encrypted_data)])


def master_action(counter, cmd, payload):
    """
    Define and handle master related actions.

    Parameters
    ----------
    counter
        message id
    cmd
        received command
    payload
        received payload

    Returns
    -------
    list
        list with cmd, counter and payload to respond
    """
    # Available commands to handle from master side
    if cmd == b'hello':
        response_cmd = b'ok'
        response_payload = f"Client {payload.decode().split(' ')[0]} added".encode()
    elif cmd == b'echo-c':
        response_cmd = b'ok-m'
        response_payload = payload
    elif cmd == b'run_keypoll':
        response_cmd = b'ok'
        response_payload = payload
    else:
        raise Exception(f"Don't know what to do with the received command {cmd}")

    response_counter = counter

    return response_cmd, response_counter, response_payload


def get_info_from_header(header: bytes):
    """
    Get information contained in the message's header.

    Parameters
    ----------
    header
        raw header to process

    Returns
    -------
    list
        counter, cmd, payload extracted from header
    """
    counter, total, cmd = struct.unpack(CLUSTER_HEADER_FORMAT, header)

    cmd = cmd.split(b' ')[0]

    return counter, total, cmd


def master_simulator(data: bytes = None):
    """
    Handler to simulate a wazuh master node behaviour.

    Parameters
    ----------
    data
        received data to handle

    Returns
    -------
    bytes
        response for the worker node
    """
    header = data[0:CLUSTER_DATA_HEADER_SIZE]
    if header != b'':
        counter, total, cmd = get_info_from_header(header)
        payload = _my_fernet.decrypt(data[CLUSTER_DATA_HEADER_SIZE:])

        return cluster_msg_build(*master_action(counter, cmd, payload))
    else:
        return b''


def process_clusterd_message(tup, command: bytes = None):
    """
    Process a clusterd message that matches the given command.

    Parameters
    ----------
    tup
        messages to process
    command
        command to look for in the tup

    Returns
    -------
    dict
        dictionary with counter, total, cmd and payload data
    """
    if isinstance(tup, tuple):
        header = tup[0][0:CLUSTER_DATA_HEADER_SIZE]
        counter, total, cmd = struct.unpack(CLUSTER_HEADER_FORMAT, header)
        if cmd == command:
            payload = _my_fernet.decrypt(tup[0][CLUSTER_DATA_HEADER_SIZE:])
            return {'counter': counter, 'total': total, 'cmd': cmd, 'payload': payload}
