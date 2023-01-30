# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import socket

from wazuh_testing.tools import ENGINE_QUEUE_SOCKET_PATH


# Engine timeouts
T_1 = 0.5

# Engine vars
# Auxiliary file used by the engine
ENGINE_ALERTS_PATH = '/var/ossec/logs/alerts/alerts-ECS.json'
ENGINE_LOG_PATH = '/tmp/engine.log'
ENGINE_PREFIX = '.*'
MODULE_NAME = 'wazuh-engine'
QUEUE = '1'
LOCATION = 'location'


def send_events_to_engine_dgram(queue=QUEUE, location=LOCATION, events=[]):
    """Send events to the engine events' socket.

    Messages must have the following format: queue:location_str:msg

    The socket's protocol is unixgram, so we just need to send the events after formatting and encoding them.

    Args:
        queue(str): string queue that creates the message to send to the socket.
        location(str): string location that creates the message to be sent to the socket.
        events (list): events to send to the socket.
    """
    # Create a unixgram socket instance
    events_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    for event in events:
        events_socket.sendto((queue + ':' + location + ':' + event).encode('utf8'), ENGINE_QUEUE_SOCKET_PATH)
