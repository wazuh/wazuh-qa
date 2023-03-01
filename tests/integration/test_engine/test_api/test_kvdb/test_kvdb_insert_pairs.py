'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: These tests will check that the engine's API allows all expected requests, verifying its behavior.
components:
    - engine
suite: test_apit2_api_call_data
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
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_database_insert_pairs.yaml')

# Engine KVDB create API configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

# Variables related to api calls and kvdbs
t1_api_call_data = engine.get_api_call_data(t1_configuration_metadata)
t1_kvdb_names = engine.get_kvdb_names(t1_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t1_api_call_data, t1_kvdb_names), ids=t1_case_ids)
def test_kvdb_insert_new_pairs(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that pairs can be inserted to existing databases using the API.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Insert the new pairs.
        - Verify the databases' content in memory.

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
            brief: Clean the provided KVDBs from memory.
        - create_predefined_kvdb:
            type: fixture
            brief: Create the KVDBs provided within the kvdb_names variable.

    assertions:
        - Check that db is loaded.
        - Check that the kvdb contains the expected pairs in memory.

    input_description:
        - The `cases_database_insert_pairs` file provides the test cases.

    expected_output:
        - Expected key-value pairs loaded
    '''
    # Verify that db is loaded in memory
    assert kvdb_names[0] in engine.get_available_kvdbs(), f"The {kvdb_names[0]} database was not created when " \
                                                          "it should."

    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Insert the new pairs to the db
    processes.run_local_command_returning_output(api_call)

    expected_kvdb_content = engine.read_kvdb_file(TEST_KVDBS_PATH, kvdb_names[0])
    pairs = {api_call_data['options']['-k']:
             api_call_data['options']['-v'] if '-v' in api_call_data['options'] else 'null'}

    expected_kvdb_content.update(pairs)
    content = {encoded_key.decode('utf-8'): encoded_value.decode('unicode_escape')
               for encoded_key, encoded_value in engine.get_kvdb_content(db_name=kvdb_names[0]).items()}

    assert expected_kvdb_content == content, 'The database has not the expected content with the new pairs.'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data', t1_api_call_data, ids=t1_case_ids)
def test_kvdb_insert_into_non_existent_db(api_call_data, clean_all_stored_kvdb):
    '''
    description: Check that pairs can be inserted to existing databases using the API.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Insert the new pairs.
        - Verify the databases' content in memory.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - api_call_data:
            type: dict
            brief: Data from the cases required to build the API calls.
        - clean_all_stored_kvdb:
            type: fixture
            brief: Clean all the KVDBs from memory.

    assertions:
        - Check that engine's output is the expected.
        - Check that the kvdb is not loaded in memory.

    input_description:
        - The `cases_database_insert_pairs` file provides the test cases.

    expected_output:
        - r".* not found or could not be loaded."
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Insert the new pairs to the db
    assert 'not found or could not be loaded' in processes.run_local_command_returning_output(api_call), \
        'The given output is not the expected: "not found or could not be loaded".'

    # Verify that the db is not in memory
    assert api_call_data['options']['-n'] not in engine.get_available_kvdbs(), \
        f"The {api_call_data['options']['-n']} database was created when it should not."
