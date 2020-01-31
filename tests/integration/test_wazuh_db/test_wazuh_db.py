# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml

from wazuh_testing.wazuh_db import callback_fim_query
from wazuh_testing.tools import WAZUH_PATH

# marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'fim_messages.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
receiver_sockets_params = [(wdb_path, 'TCP')]
monitored_sockets_params = [(wdb_path, 'TCP')]
used_daemons = ['wazuh-db']


# tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_wazuh_db_messages(configure_environment_standalone_daemons, create_unix_sockets, test_case):
    """ Check wazuh-db messages

    * This test checks that every input message in wazuh-db socket generates the adequate output to wazuh-db socket
    """
    for stage in test_case:
        expected = stage['output']
        receiver_sockets[0].send([stage['input']], size=True)
        response = monitored_sockets[0].start(timeout=5, callback=callback_fim_query).result()
        assert response == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
