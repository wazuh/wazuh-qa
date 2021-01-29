# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables
logtest_sock = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'analysis'))
receiver_sockets_params = [(logtest_sock, 'AF_UNIX', 'TCP')]
receiver_sockets = None
msg_get_config = "getconfig rule_test"


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
def test_get_configuration_sock(get_configuration, configure_environment, restart_wazuh, connect_to_sockets_function):
    """Check analisis Unix socket returns the correct Logtest configuration
    """

    configuration = get_configuration['sections'][0]['elements']

    if 'invalid_threads_conf' in get_configuration['tags']:
        configuration[1]['threads']['value'] = '128'
    elif 'invalid_users_conf' in get_configuration['tags']:
        configuration[2]['max_sessions']['value'] = '500'
    elif 'invalid_timeout_conf' in get_configuration['tags']:
        configuration[3]['session_timeout']['value'] = '31536000'

    receiver_sockets[0].send(msg_get_config, True)
    msg_recived = receiver_sockets[0].receive().decode()

    matched = re.match(r'.*{"enabled":"(\S+)","threads":(\d+),"max_sessions":(\d+),"session_timeout":(\d+)}}',
                       msg_recived)
    assert matched is not None, f'Real message was: "{msg_recived}"'

    assert matched.group(1) == configuration[0]['enabled']['value'], f"""Expected value in enabled tag:
           '{configuration[0]['enabled']['value']}'. Value received: '{matched.group(1)}'"""

    assert matched.group(2) == configuration[1]['threads']['value'], f"""Expected value in threads tag:
           '{configuration[1]['threads']['value']}'. Value received: '{matched.group(2)}'"""

    assert matched.group(3) == configuration[2]['max_sessions']['value'], f"""Expected value in max_sessions tag:
           '{configuration[2]['max_sessions']['value']}'. Value received: '{matched.group(3)}'"""
    assert matched.group(4) == configuration[3]['session_timeout']['value'], f"""Expected value in session_timeout tag:
           '{configuration[3]['session_timeout']['value']}'. Value received: '{matched.group(4)}'"""
