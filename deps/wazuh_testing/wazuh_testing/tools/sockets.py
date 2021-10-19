# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import socket
import struct
import time
import json
from os import path

from wazuh_testing.tools import WAZUH_PATH, ACTIVE_RESPONSE_SOCKET_PATH
from wazuh_testing.tools.utils import retry

request_socket = path.join(WAZUH_PATH, 'queue', 'sockets', 'request')
request_protocol = "tcp"


class WazuhSocket:
    def __init__(self, socket_file=request_socket):
        """Encapsulate wazuh-socket communication (header with message size)

        Args:
            socket_file (str): Path of the file socket.
        """
        self.file = socket_file

    def send(self, msg, response_size=4):
        """Send and receive data to wazuh-socket (header with message size)

        Args:
            msg (str): data to send

        Returns:
            str: received data
        """
        @retry(socket.error)
        def connection(_socket, request):
            _socket.connect(request)

        @retry(socket.error)
        def send_msg(_socket, msg):
            _socket.send(msg)

        @retry(ValueError)
        def recv_response(_socket, size):
            size = struct.unpack("<I", _socket.recv(size, socket.MSG_WAITALL))[0]
            recv_msg = _socket.recv(size, socket.MSG_WAITALL)
            if recv_msg == '':
                raise ValueError
            return recv_msg

        msg_json = json.dumps(msg)

        try:
            wazuh_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            encoded_msg = msg_json.encode('utf-8')
            request_msg = struct.pack("<I", len(encoded_msg)) + encoded_msg

            connection(wazuh_socket, self.file)
            send_msg(wazuh_socket, request_msg)
            response = recv_response(wazuh_socket, response_size)
            wazuh_socket.close()

            return json.loads(response)

        except Exception:
            raise ConnectionError


def send_request(msg_request, response_size=100, wazuh_socket=request_socket):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    request_msg = struct.pack('<I', len(msg_request)) + msg_request.encode()

    @retry(socket.error)
    def connection(_socket, request):
        _socket.connect(request)

    @retry(socket.error)
    def send_msg(_socket, msg):
        _socket.send(msg)

    @retry(ValueError)
    def recv_response(_socket, size):
        answer = _socket.recv(size).decode()
        if answer == '':
            raise ValueError
        return answer

    connection(sock, wazuh_socket)
    send_msg(sock, request_msg)
    response = recv_response(sock, response_size)

    sock.close()

    return response


def send_active_response_message(active_response_command):
    """Send active response message to `/var/ossec/queue/alerts/ar` socket.

    Args:
        active_response_command (str): Active response message.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    sock.connect(ACTIVE_RESPONSE_SOCKET_PATH)
    sock.send(f"{active_response_command}".encode())
    sock.close()


def wait_for_tcp_port(port, host='localhost', timeout=10):
    """Wait until a port starts accepting TCP connections.
    Args:
        port (int): Port number.
        host (str): Host address on which the port should be listening. Default 'localhost'
        timeout (float): In seconds. How long to wait before raising errors.
    Raises:
        TimeoutError: The port isn't accepting connection after time specified in `timeout`.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock.connect((host, port))
            sock.close()
            return
        except ConnectionRefusedError:
            time.sleep(1)


    raise TimeoutError(f'Waited too long for the port {port} on host {host} to start accepting messages')