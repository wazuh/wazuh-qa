# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import shutil
import re

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import set_section_wazuh_conf
import wazuh_testing.tools.configuration as conf


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/')
messages_path = os.path.join(test_data_path, 'rules_verbose.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]


# Fixtures
@pytest.fixture(scope='function')
def configure_rules_list(get_configuration, request):
    """
    Configure a custom rules for testing.
    Restart Wazuh is not needed for applying the configuration is optional.
    """

    # save current rules
    shutil.copy('/var/ossec/etc/rules/local_rules.xml',
                '/var/ossec/etc/rules/local_rules.xml.cpy')

    file_test = get_configuration['rule_file']
    # copy test rules
    shutil.copy(test_data_path + file_test, '/var/ossec/etc/rules/local_rules.xml')
    shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")

    yield

    # restore previous configuration
    shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy', '/var/ossec/etc/rules/local_rules.xml')
    shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_rules_verbose(get_configuration, configure_rules_list, connect_to_sockets_function):
    """Check that every test case run on logtest generates the adequate output """

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = json.loads(response)

    assert result['error'] == 0
    assert result['data']['output']['rule']['id'] == get_configuration['rule_id']

    if 'verbose_mode' in get_configuration and get_configuration['verbose_mode'] is True:
        if 'rules_debug' in result['data']:
            assert result['data']['rules_debug'][-7] == "Trying rule: 880000 - Parent rules verbose"
            assert result['data']['rules_debug'][-6] == "*Rule 880000 matched"
            assert result['data']['rules_debug'][-5] == "*Trying child rules"
            assert result['data']['rules_debug'][-4] == "Trying rule: 880001 - test last_match"
            assert result['data']['rules_debug'][-3] == "*Rule 880001 matched"
            assert result['data']['rules_debug'][-2] == "*Trying child rules"
            assert result['data']['rules_debug'][-1] == "Trying rule: 880002 - test_child test_child"
        else:
            assert False, "The rules_debug filed was not found in the response data"

    else:
        assert 'rules_debug' not in result['data']

    if 'warning_message' in get_configuration:
        r = re.compile(get_configuration['warning_message'])
        match_list = list(filter(r.match, result['data']['messages']))
        assert match_list
