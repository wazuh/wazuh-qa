# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing.analysis import callback_wdb, callback_fim_error, validate_analysis_event
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, FileMonitor

# All tests in this module apply to linux only
pytestmark = pytest.mark.linux

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
messages_path = os.path.join(test_data_path, 'messages.yaml')
with open(messages_path) as f:
    messages = yaml.safe_load(f)
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
monitored_sockets_params = [(wdb_path, 'TCP')]
receiver_sockets_params = [(analysis_path, 'UDP')]
used_daemons = ['ossec-analysisd']


# tests

@pytest.mark.parametrize('message_', [
    message_ for message_ in messages
])
def test_event_messages(configure_environment_standalone_daemons, create_unix_sockets, message_):
    """

    """
    receiver_sockets[0].send([message_['input']])
    response = monitored_sockets[0].start(timeout=5, callback=callback_wdb).result()
    print(response)
    event = wazuh_log_monitor.start(timeout=10, callback=callback_fim_error).result()
    validate_analysis_event(event)
