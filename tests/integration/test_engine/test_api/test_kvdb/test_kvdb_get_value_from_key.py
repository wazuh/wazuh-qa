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
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_get_key_value.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_get_non_existent_key_value.yaml')

# Engine KVDB create API configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)

# Variables related to api calls and kvdbs
t1_api_call_data = engine.get_api_call_data(t1_configuration_metadata)
t1_kvdb_names = engine.get_kvdb_names(t1_configuration_metadata)
t2_api_call_data = engine.get_api_call_data(t2_configuration_metadata)
t2_kvdb_names = engine.get_kvdb_names(t2_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t1_api_call_data, t1_kvdb_names), ids=t1_case_ids)
def test_kvdb_get_key_value(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Get the value for a given key within an existing database.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Obtain the key value from db memory.
        - Verify the API output.

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
        - Check that API's output is the expected.

    input_description:
        - The `cases_kvdb_api_database_get_key_value` file provides the test cases.

    expected_output:
        - r"Key: .*\nValue: \".*\"\n"
    '''
    # Verify that db is loaded in memory
    assert kvdb_names[0] in engine.get_available_kvdbs(), f"The {kvdb_names[0]} database was not created when " \
                                                          "it should."

    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Get the Tcase key's value
    api_output = processes.run_local_command_returning_output(api_call)
    key_value = engine.get_kvdb_value(db_name=kvdb_names[0], key=api_call_data['options']['-k']).decode()

    # Build the expected output message
    expected_api_output = f"Key: {api_call_data['options']['-k']}\nValue: \"{key_value}\"\n"

    # Verify that the API call returns the expected message with the same value that the db has
    assert api_output == expected_api_output, f"The api call does not match the expected output:\n{expected_api_output}"


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data', t1_api_call_data, ids=t1_case_ids)
def test_kvdb_get_key_value_from_non_existent_db(api_call_data, clean_all_stored_kvdb):
    '''
    description: Get the value for a given key within a non-existent database.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Obtain the key value from db memory.
        - Verify the API output.

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
        - Check that API's output is the expected.
        - Check that there is no db.

    input_description:
        - The `cases_kvdb_api_database_get_key_value` file provides the test cases.

    expected_output:
        - r".* not found or could not be loaded."
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that API call failed founding the db
    assert 'not found or could not be loaded.' in processes.run_local_command_returning_output(api_call), \
        'The given output is not the expected: "not found or could not be loaded".'

    # Verify that the database is not in memory
    assert api_call_data['options']['-n'] not in engine.get_available_kvdbs(), \
        f"The {api_call_data['options']['-n']} database was created when it should not."


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t2_api_call_data, t2_kvdb_names), ids=t2_case_ids)
def test_kvdb_get_key_value_for_non_existent_key(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Get the value for a given key that does not exist in a database.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Obtain the key value from db memory.
        - Verify the API output.

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
        - Check that API's output is the expected.

    input_description:
        - The `cases_kvdb_api_database_get_non_existent_key_value` file provides the test cases.

    expected_output:
        - r"Cannot read value .*"
    '''
    # Verify that db is loaded in memory
    assert kvdb_names[0] in engine.get_available_kvdbs(), f"The {kvdb_names[0]} database was not created when " \
                                                          "it should."

    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Try to get a value for a non-existent key
    assert 'Cannot read value' in processes.run_local_command_returning_output(api_call), \
        'The given output is not the expected. It should be like "Cannot read value .*"'
