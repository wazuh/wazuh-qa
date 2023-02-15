'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: These tests will check that the engine's API allows all expected requests, verifying its behavior.
components:
    - engine
suite: test_api
targets:
    - manager
daemons:
    - wazuh-engine
os_platform:
    - linux
os_version:
    - Ubuntu Focal
references:
    - https://github.com/wazuh/wazuh/issues/11334
    - https://python-rocksdb.readthedocs.io/en/latest/api/database.html#database-interactions
tags:
    - engine
    - kvdb
    - rocksdb
'''
import os
import pytest

from wazuh_testing import processes
from wazuh_testing.modules import engine
from wazuh_testing.tools.configuration import get_test_cases_data

# Reference paths
TEST_KVDBS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'data', 'kvdbs')
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_list_and_filtering.yaml')

# Engine events configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

# Variables related to api calls and kvdbs
api_call_data = engine.get_api_call_data(t1_configuration_metadata)
kvdb_names = engine.get_kvdb_names(t1_configuration_metadata)


def get_list_expected_output(kvdb_names, options):
    """Get the output that the engine would show with the given kvdbs.

    Args:
        kvdb_names(list): KVDBs that are loaded.
        options(dict): Test case options.
    """
    n_kvdbs = 0
    actual_n_kvdb = 0
    expected_output = ''

    if '-n' in options:
        for kvdb_name in kvdb_names:
            if options['-n'] in kvdb_name:
                n_kvdbs += 1
    else:
        # If there is no filtering, all the kvdbs will be listed
        n_kvdbs = len(kvdb_names)

    for kvdb_name in kvdb_names:
        current_output = f",\"{kvdb_name}\"" if actual_n_kvdb != 0 else f"\"{kvdb_name}\""
        if '-n' in options:
            if options['-n'] in kvdb_name:
                expected_output += current_output
                actual_n_kvdb += 1
        else:
            expected_output += current_output
            actual_n_kvdb += 1

    return f"[{expected_output}]\n" if actual_n_kvdb != 0 else ''


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(api_call_data, kvdb_names), ids=t1_case_ids)
def test_kvdb_list(request, api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that KVDBs can be listed when loaded as expected.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs
        - Verify the created databases can be listed with the engine.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - api_call_data:
            type: dict
            brief: Data from the cases required to build the API calls.
        - kvdb_names:
            type: str
            brief: Database name to be created.
        - clean_stored_kvdb:
            type: fixture
            brief: Clean the KVDBs from memory.
        - create_predefined_kvdb:
            type: fixture
            brief: Create the cases' databases using the `kvdb_names` parameter.

    assertions:
        - Check that the engine's output matches with the expected.

    input_description:
        - The `cases_kvdb_api_list_and_filtering` file provides the test cases.

    expected_output:
        - r"Databases found: .*"
        - r".*/.* - .*"
.
    '''
    if request.node.callspec.id == 'Verify listing a non-existent kvdb':
        pytest.xfail('The list command\'s output is not correct now.')

    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    kvdbs_to_list = kvdb_names if request.node.callspec.id != 'Verify listing all the existent kvdbs' \
        else kvdb_names + engine.ENGINE_ENV_KVDBS

    # Verify that list command output is the expected
    assert processes.run_local_command_returning_output(api_call) == \
        get_list_expected_output(kvdbs_to_list, api_call_data['options'] if 'options' in api_call_data else {})


@pytest.mark.tier(level=0)
@pytest.mark.xfail(reason='List command\'s output when there are no kvdbs loaded is not correct.')
@pytest.mark.parametrize('api_call_data', api_call_data, ids=t1_case_ids)
def test_kvdb_list_no_loaded_kvdbs(api_call_data, clean_all_stored_kvdb):
    '''
    description: Check that listing KVDBs not loaded on memory generates the expected output.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs
        - Verify the created databases can be listed with the engine.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - api_call_data:
            type: dict
            brief: Data from the cases required to build the API calls.
        - kvdb_names:
            type: str
            brief: Database name to be created.
        - clean_stored_kvdb:
            type: fixture
            brief: Clean the KVDBs from memory.
        - create_predefined_kvdb:
            type: fixture
            brief: Create the cases' databases using the `kvdb_names` parameter.

    assertions:
        - Check that the engine's output matches with the expected.

    input_description:
        - The `cases_kvdb_api_list_and_filtering` file provides the test cases.

    expected_output:
        - 'Databases found: 0'
.
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that list command output is the expected
    assert processes.run_local_command_returning_output(api_call) == \
        get_list_expected_output([], api_call_data['options'] if 'options' in api_call_data else {})
