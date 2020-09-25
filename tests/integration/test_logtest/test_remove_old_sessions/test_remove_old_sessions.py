# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor, SocketController
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.logtest import (callback_logtest_started,
                                   callback_remove_session,
                                   callback_session_initialized)


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
logtest_sock = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'logtest'))

msg_create_session = """{"version":1, "command":"log_processing", "parameters":{
"event": "Oct 15 21:07:56 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928",
"log_format": "syslog", "location": "master->/var/log/syslog"}}"""


# Function to manage the comunication with Wazuh-logtest
def create_connection():
    return SocketController(address=logtest_sock, family='AF_UNIX', connection_protocol='TCP')

def remove_connection(connection):
    connection.close()
    del connection


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
def test_remove_old_session(get_configuration, configure_environment, restart_wazuh):
    """
    Create more sessions than allowed and wait for the message which
    informs that Wazuh-logtest has removed the oldest session.
    """

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_logtest_started,
                            error_message='Event not found')

    max_sessions = int(get_configuration['sections'][0]['elements'][2]['max_sessions']['value'])

    for i in range(0, max_sessions):

        receiver_socket = create_connection()
        receiver_socket.send(msg_create_session, True)
        msg_recived = receiver_socket.receive().decode()
        remove_connection(receiver_socket)

        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_session_initialized,
                                error_message='Event not found')

    # This session should do Wazuh-logtest to remove the oldest session
    receiver_socket = create_connection()
    receiver_socket.send(msg_create_session, True)
    msg_recived = receiver_socket.receive().decode()
    remove_connection(receiver_socket)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_remove_session,
                            error_message='Event not found')
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_session_initialized,
                            error_message='Event not found')
