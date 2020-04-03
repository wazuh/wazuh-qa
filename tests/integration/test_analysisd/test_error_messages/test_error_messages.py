# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.analysis import callback_fim_error
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'error_messages.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables

log_monitor_paths = [LOG_FILE_PATH]
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))

receiver_sockets_params = [(analysis_path, 'AF_UNIX', 'UDP')]

mitm_analysisd = ManInTheMiddle(address=analysis_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('ossec-analysisd', mitm_analysisd, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_error_messages(configure_mitm_environment, connect_to_sockets_module, test_case: list):
    """Check that every input message in analysisd socket generates the adequate output to wazuh-db socket

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys)
    """
    for stage in test_case:
        receiver_sockets[0].send(stage['input'])
        result = log_monitors[0].start(timeout=4*global_parameters.default_timeout,
                                       callback=callback_fim_error).result()
        assert result == stage['output'], 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1,
                                                                                 stage['stage'])
