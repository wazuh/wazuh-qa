# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re

import pytest

from wazuh_testing.tools import SocketMonitor
from wazuh_testing.tools import WAZUH_PATH

# All tests in this module apply to linux only
pytestmark = pytest.mark.linux

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'messages.json')
with open(messages_path) as f:
    messages = json.load(f)
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))


# tests

def test_event_messages():
    """

    """
    regex = r'^([^{]+)(\{.+)$'
    with SocketMonitor(wdb_path, timeout=5, socket_type='reader') as wdb, \
            SocketMonitor(analysis_path, timeout=5, socket_type='writer') as queue:
        for key, message_ in messages.items():
            queue.send([message_['input']])
            response = wdb.receive(1)[0]
            response = response.decode().rstrip('\x00')
            try:
                response_match = re.search(regex, response)
                response_header, response_json_body = response_match.groups()
                expected = re.search(regex, message_['output'])
                expected_header, expected_json_body = expected.groups()
                assert response_header == expected_header
                assert json.loads(response_json_body) == json.loads(expected_json_body)
            except (AttributeError, json.decoder.JSONDecodeError):
                assert response == message_['output']
