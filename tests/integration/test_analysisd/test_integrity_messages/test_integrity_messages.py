# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing import global_parameters
from wazuh_testing.analysis import callback_analysisd_message, validate_analysis_integrity_state, \
    callback_wazuh_db_integrity
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'integrity_messages.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables

log_monitor_paths = [LOG_FILE_PATH]
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))

receiver_sockets_params = [(analysis_path, 'AF_UNIX', 'UDP')]

mitm_wdb = ManInTheMiddle(address=wdb_path, family='AF_UNIX', connection_protocol='TCP')
mitm_analysisd = ManInTheMiddle(address=analysis_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('wazuh-db', mitm_wdb, True), ('wazuh-analysisd', mitm_analysisd, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_integrity_messages(configure_sockets_environment, connect_to_sockets_module, wait_for_analysisd_startup,
                            test_case: list):
    """Check that every input message in analysisd socket generates the adequate output to wazuh-db socket.

    The function validate_analysis_integrity_state is a function responsible for checking that the output follows a
    certain jsonschema.

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys)
    """
    for stage in test_case:
        expected = callback_analysisd_message(stage['output'])
        receiver_sockets[0].send(stage['input'])
        response = monitored_sockets[0].start(timeout=3 * global_parameters.default_timeout,
                                              callback=callback_wazuh_db_integrity).result()
        assert response == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
        stage['validate'] and validate_analysis_integrity_state(response[2])
