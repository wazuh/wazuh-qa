# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import socket
import struct
from os import path
from wazuh_testing.tools import WAZUH_PATH, WAZUH_SOCKETS

request_socket = path.join(WAZUH_PATH, 'queue', 'sockets', 'request')
request_protocol = "tcp"


def send_request(msg_request, response_size=100):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    request_msg = struct.pack('<I', len(msg_request)) + msg_request.encode()

    sock.connect(request_socket)
    sock.send(request_msg)
    response = sock.recv(response_size).decode()
    sock.close()

    return response

def send_ar_message(ar_command):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    ar_socket = WAZUH_SOCKETS['wazuh-ar'][0]

    sock.connect(ar_socket)
    sock.send(f"{ar_command}".encode())
    sock.close()

