# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing.analysis import callback_fim_event_alert, callback_analysisd_message, validate_analysis_alert
from wazuh_testing.tools import WAZUH_LOGS_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor

# All tests in this module apply to linux only
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
wazuh_log_monitor = FileMonitor(alerts_json)
messages_path = os.path.join(test_data_path, 'event_messages.yaml')
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
    """ Checks the event messages handling by analysisd.

    The variable messages is a yaml file that contains the input and the expected output for every test case.
    The function validate_analysis_integrity_state is a function responsible for checking that the output follows a
    certain jsonschema.

    """
    expected = callback_analysisd_message(message_['output'])
    receiver_sockets[0].send([message_['input']])
    response = monitored_sockets[0].start(timeout=5, callback=callback_analysisd_message).result()
    assert response == expected, 'Failed test case type: {}'.format(message_['type'])
    alert = wazuh_log_monitor.start(timeout=10, callback=callback_fim_event_alert).result()
    validate_analysis_alert(alert)
