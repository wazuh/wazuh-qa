# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import callback_fim_query

# marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# variables

wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
receiver_sockets_params = [(wdb_path, 'TCP')]
monitored_sockets_params = [(wdb_path, 'TCP')]
used_daemons = ['wazuh-db']

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_files = os.listdir(test_data_path)
module_tests, module_names = list(), list()
for file in messages_files:
    with open(os.path.join(test_data_path, file)) as f:
        module_tests.append((yaml.safe_load(f), file.split("_")[0]))

# tests


@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_wazuh_db_messages(configure_environment_standalone_daemons, create_unix_sockets, test_case: list):
    """Check that every input message in wazuh-db socket generates the adequate output to wazuh-db socket

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys)
    """
    for stage in test_case:
        expected = stage['output']
        receiver_sockets[0].send([stage['input']], size=True)
        response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                              callback=callback_fim_query).result()
        assert response == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
