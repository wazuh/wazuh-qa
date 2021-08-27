# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import shutil
import re

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH, LOGTEST_SOCKET_PATH, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP, LOCAL_RULES_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/')
messages_path = os.path.join(test_data_path, 'rules_verbose.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]

local_rules_debug_messages = ['Trying rule: 880000 - Parent rules verbose', '*Rule 880000 matched',
                              '*Trying child rules', 'Trying rule: 880001 - test last_match', '*Rule 880001 matched',
                              '*Trying child rules', 'Trying rule: 880002 - test_child test_child']


# Fixtures
@pytest.fixture(scope='function')
def configure_rules_list(get_configuration, request):
    """
    Configure a custom rules for testing.
    Restart Wazuh is not needed for applying the configuration is optional.
    """

    # save current rules
    shutil.copy(LOCAL_RULES_PATH, LOCAL_RULES_PATH+'.cpy')

    file_test = get_configuration['rule_file']
    # copy test rules
    shutil.copy(test_data_path + file_test, LOCAL_RULES_PATH)
    shutil.chown(LOCAL_RULES_PATH, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)

    yield

    # restore previous configuration
    shutil.move(LOCAL_RULES_PATH+'.cpy', LOCAL_RULES_PATH)
    shutil.chown(LOCAL_RULES_PATH, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_rules_verbose(get_configuration, configure_rules_list, connect_to_sockets_function):
    """Check the correct behaviour of logtest `rules_debug` field.

    This test writes different inputs at the logtest socket and checks the responses to be the expected.
    """

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = json.loads(response)

    assert result['error'] == 0
    assert result['data']['output']['rule']['id'] == get_configuration['rule_id']

    if 'verbose_mode' in get_configuration and get_configuration['verbose_mode']:
        if 'rules_debug' in result['data']:
            assert result['data']['rules_debug'][-len(local_rules_debug_messages):] == local_rules_debug_messages
        else:
            assert False, 'The rules_debug field was not found in the response data'

    else:
        assert 'rules_debug' not in result['data']

    if 'warning_message' in get_configuration:
        r = re.compile(get_configuration['warning_message'])
        match_list = list(filter(r.match, result['data']['messages']))
        assert match_list, 'The warning message was not found in the response data'
