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
CLUSTER_CMD_HEADER_SIZE = 12
CLUSTER_HEADER_FORMAT = '!2I{}s'.format(CLUSTER_CMD_HEADER_SIZE)
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
    return _process_clusterd_message(item, command=b'run_keypoll')


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


def cluster_msg_build(cmd: bytes = None, counter: int = None, payload: bytes = None, encrypt=True) -> bytes:
    """
    Build a message using cluster protocol.

    Parameters
    ----------
    cmd : bytes
        command to send
    counter : int
        message id
    payload : bytes
        data to send
    encrypt : bool
        whether to use fernet encryption or not

    Returns
    -------
    bytes
        built message
    """
    cmd_len = len(cmd)
    if cmd_len > CLUSTER_CMD_HEADER_SIZE:
        raise Exception("Length of command '{}' exceeds limit ({}/{}).".format(cmd, cmd_len,
                                                                               CLUSTER_CMD_HEADER_SIZE))

    encrypted_data = _my_fernet.encrypt(payload) if encrypt else payload
    out_msg = bytearray(CLUSTER_DATA_HEADER_SIZE + len(encrypted_data))

    # Add - to command until it reaches cmd length
    cmd = cmd + b' ' + b'-' * (CLUSTER_CMD_HEADER_SIZE - cmd_len - 1)

    out_msg[:CLUSTER_DATA_HEADER_SIZE] = struct.pack(CLUSTER_HEADER_FORMAT, counter, len(encrypted_data), cmd)
    out_msg[CLUSTER_DATA_HEADER_SIZE:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)] = encrypted_data

    return bytes(out_msg[:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)])


def _master_action(counter: int = None, cmd: bytes = None, payload: bytes = None, **kwargs):
    """
    Define and handle master related actions.

    Parameters
    ----------
    counter : int
        message id
    cmd : bytes
        received command
    payload : bytes
        received payload

    Returns
    -------
    dict
        cmd, counter and payload to respond
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

    return {'cmd': response_cmd, 'counter': response_counter, 'payload': response_payload}


def _get_info_from_header(data: bytes):
    """
    Get information contained in the message's header.

    Parameters
    ----------
    data
        raw data to process

    Returns
    -------
    dict
        counter, cmd, total extracted from header
    """
    counter, total, cmd = struct.unpack(CLUSTER_HEADER_FORMAT, data[0:CLUSTER_DATA_HEADER_SIZE])
    cmd = cmd.split(b' ')[0]

    return {'counter': counter, 'total': total, 'cmd': cmd}


def _cluster_message_decompose(data: bytes):
    """
    Get all information contained in the cluster message.

    Parameters
    ----------
    data
        raw cluster data to process

    Returns
    -------
    dict
        header + decrypted payload from data
    """
    decomposed_message = _get_info_from_header(data)
    decomposed_message['payload'] = _my_fernet.decrypt(data[CLUSTER_DATA_HEADER_SIZE:])

    return decomposed_message


def master_simulator(data: bytes):
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
        return cluster_msg_build(**_master_action(**_cluster_message_decompose(data)))
    else:
        return b''


def _process_clusterd_message(tup, command: bytes = None):
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
        decomposed_data = _cluster_message_decompose(tup[0])
        if decomposed_data['cmd'] == command:
            return decomposed_data
