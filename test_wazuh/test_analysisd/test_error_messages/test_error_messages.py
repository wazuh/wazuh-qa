# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing.analysis import callback_fim_error
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor

# All tests in this module apply to linux only
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
messages_path = os.path.join(test_data_path, 'error_messages.yaml')
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
def test_error_messages(configure_environment_standalone_daemons, create_unix_sockets, message_):
    """ Checks the error messages handling by analysisd.
    The variable messages is a yaml file that contains the input and the expected output for every test case.

    """
    receiver_sockets[0].send([message_['input']])
    result = wazuh_log_monitor.start(timeout=20, callback=callback_fim_error).result()
    assert result == message_['output'], 'Failed test case type: {}'.format(message_['type'])
