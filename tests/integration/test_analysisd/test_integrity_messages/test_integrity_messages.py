# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing import global_parameters
from wazuh_testing.analysis import callback_analysisd_message, validate_analysis_integrity_state
from wazuh_testing.tools import WAZUH_PATH

# marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'integrity_messages.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
monitored_sockets_params = [(wdb_path, 'TCP')]
receiver_sockets_params = [(analysis_path, 'UDP')]
used_daemons = ['ossec-analysisd']


# tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_integrity_messages(configure_environment_standalone_daemons, create_unix_sockets, test_case: list):
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
        receiver_sockets[0].send([stage['input']])
        response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                              callback=callback_analysisd_message).result()
        assert response == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
        stage['validate'] and validate_analysis_integrity_state(response[2])
