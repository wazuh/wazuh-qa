# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import socket
import struct
from wazuh_testing.tools.services import wait_for_remote_connection

request_socket = '/var/ossec/queue/sockets/request'
request_protocol = "tcp"


def send_request(msg_request, response_size=100):
    request_retries = 10
    while request_retries > 0:
        request_retries -= 1
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        request_msg = struct.pack('<I', len(msg_request)) + msg_request.encode()

        wait_for_remote_connection(protocol=request_protocol)

        sock.connect(request_socket)
        sock.send(request_msg)
        response = sock.recv(response_size).decode()
        sock.close()
        if response != '':
            return response
        time.sleep(1)
