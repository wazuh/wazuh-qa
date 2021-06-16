# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import os
import sys
import pytest
from wazuh_testing.tools.utils import lower_case_key_dictionary_array
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.tier(level=0)]
LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_active_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables
logcollector_sock = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logcollector'))
receiver_sockets_params = [(logcollector_sock, 'AF_UNIX', 'TCP')]
receiver_sockets = None
msg_get_config = "getconfig localfile"

location = '/tmp/test.txt'

tcases = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
]
macos_tcases = [{'LOCATION': 'macos', 'LOG_FORMAT': 'macos'}]

if sys.platform == 'darwin':
    tcases += macos_tcases

metadata = lower_case_key_dictionary_array(tcases)
parameters = tcases

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)

configuration_ids = [f"{x['location']}_{x['log_format']}" for x in metadata]


# Fixture
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_get_configuration_sock(get_configuration, configure_environment, restart_wazuh, connect_to_sockets_function):
    """Check logcollector Unix socket returns the correct localfile configuration"""

    configuration = get_configuration['metadata']

    receiver_sockets[0].send(msg_get_config, True)
    msg_received = receiver_sockets[0].receive().decode('latin-1')

    matched = re.match(r'.*{"file":"(\S+)","logformat":"(\S+)","ignore_binaries":"no","only-future-events":"yes",'
                       r'"target":\["agent"\]}.*',msg_received)

    assert matched is not None, f'Real message was: "{msg_received}"'

    assert matched.group(1) == configuration['location'], f"""Expected value in location option:
           '{configuration['location']}'. Value received: '{matched.group(1)}'"""

    assert matched.group(2) == configuration['log_format'], f"""Expected value in location option:
              '{configuration['log_format']}'. Value received: '{matched.group(2)}'"""

