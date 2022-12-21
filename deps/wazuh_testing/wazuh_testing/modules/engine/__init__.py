# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import socket

from wazuh_testing.tools import ENGINE_QUEUE_SOCKET_PATH


# engine timeouts
T_1 = 0.5

# engine vars
ENGINE_ALERTS_PATH = '/var/ossec/logs/alerts/alerts-ECS.json'  # the engine uses this file during the dev phase
ENGINE_LOG_PATH = '/tmp/engine.log'
ENGINE_PREFIX = '.*'
MODULE_NAME = 'wazuh-engine'
QUEUE = '1'
LOCATION = 'location'


def send_events_to_engine_dgram(events):
    """Send events to the engine events' socket.

    The messages must follow the following format: queue:location_str:msg

    The socket's protocol is unixgram, so we just need to send the events after formatting and encoding them.

    Args:
        events (list): Events that will be sent to the socket.
    """
    # Create a unixgram socket instance
    events_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    for event in events:
        # Build the message with the expected format: {queue:location_str:msg}
        msg_formatted = (QUEUE + ':' + LOCATION + ':' + event).encode('utf8')

        # Send the encoded message to the engine's events socket
        events_socket.sendto(msg_formatted, ENGINE_QUEUE_SOCKET_PATH)
