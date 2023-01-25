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
from wazuh_testing.tools.configuration import get_test_cases_data, update_configuration_template


# Reference paths
TEST_KVDBS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'data', 'kvdbs')
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_creation.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_creation_using_invalid_file_format.yaml')

# Engine KVDB create API configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

# Engine KVDB create API using invalid file format as input configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)

# Replace the custom variables values
t1_tags_to_replace = ['PATH_TO_KVDB_JSON_FILE']
t1_new_tags_values = [TEST_KVDBS_PATH]
t1_configuration_metadata = update_configuration_template(t1_configuration_metadata,
                                                          t1_tags_to_replace, t1_new_tags_values)
t2_tags_to_replace = ['PATH_TO_KVDB_TXT_FILE', 'PATH_TO_KVDB_JSON_FILE']
t2_new_tags_values = [TEST_KVDBS_PATH, TEST_KVDBS_PATH]
t2_configuration_metadata = update_configuration_template(t2_configuration_metadata,
                                                          t2_tags_to_replace, t2_new_tags_values)

# Variables related to api calls and kvdbs
t1_api_call_data = engine.get_api_call_data(t1_configuration_metadata)
t1_kvdb_names = engine.get_kvdb_names(t1_configuration_metadata)
t2_api_call_data = engine.get_api_call_data(t2_configuration_metadata)
t2_kvdb_names = engine.get_kvdb_names(t2_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t1_api_call_data, t1_kvdb_names))
def test_kvdb_create(api_call_data, kvdb_names, clean_stored_kvdb):
    '''
    description: Check that KVDBs can be created as expected using a JSON file as input.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs
        - Verify the created databases' content on memory.

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

    assertions:
        - Check that the database content matches with the expected.

    input_description:
        - The `cases_kvdb_api_database_creation` file provides the test cases.

    expected_output:
        - The KVDB content collected via rocksdb API matches with the expected content.
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    processes.run_local_command_returning_output(api_call)

    expected_kvdb_content = engine.read_kvdb_file(TEST_KVDBS_PATH, kvdb_names[0])
    loaded_kvdb = {encoded_key.decode('utf-8'): encoded_value.decode('unicode_escape')
                   for encoded_key, encoded_value in engine.get_kvdb_content(db_name=kvdb_names[0]).items()}

    # Verify that the created kvdb has the expected pairs
    assert expected_kvdb_content == loaded_kvdb, 'The created db has not the expected content.'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t1_api_call_data, t1_kvdb_names))
def test_kvdb_create_already_existing_db(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that KVDBs that already exists can't be created again and it is not modified with the new data.
                 After the db is created for the first time (fixture), the test will insert new data so we can confirm
                 that when we try to create it again using the json input file it does not.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Insert a new pair to the already existing db.
        - Try to create the already existing db again.
        - Verify the already existing database content did not change.
        - Verify that given output command is the correct one.

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
        - Check that the engine output is the expected.
        - Check that the database content did not change.

    input_description:
        - The `cases_kvdb_api_database_creation` file provides the test cases.

    expected_output:
        - f"Database '.*' already exists\n"
    '''
    # Add new changes to the already loaded db schema
    api_call_insert_new_pair = engine.create_api_call('kvdb', 'insert', {'-n': kvdb_names[0], '-k': 'akey',
                                                                         '-v': 'avalue'})

    assert processes.run_local_command_returning_output(api_call_insert_new_pair) == 'Key-value successfully written ' \
                                                                                     'to the database\n'

    # Get the kvdb content before we try to recreate it
    expected_kvdb_content = {encoded_key.decode('utf-8'): encoded_value.decode('unicode_escape')
                             for encoded_key, encoded_value in engine.get_kvdb_content(db_name=kvdb_names[0]).items()}

    # Create api call that will create the kvdb
    api_call_existent_db = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                                  api_call_data['options'] if 'options' in api_call_data
                                                  else {})

    # Verify that the create command prompt that given kvdb already exists
    assert processes.run_local_command_returning_output(api_call_existent_db) == f"Database '{kvdb_names[0]}' " \
                                                                                 "already exists\n"

    # Get the current kvdb content
    kvdb_content = {encoded_key.decode('utf-8'): encoded_value.decode('unicode_escape')
                    for encoded_key, encoded_value in engine.get_kvdb_content(db_name=kvdb_names[0]).items()}

    # Verify that already existent db has not been modified with creation attempt
    assert expected_kvdb_content == kvdb_content, 'The already existing kvdb has been created again.'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t2_api_call_data, t2_kvdb_names))
def test_create_using_invalid_file_format(api_call_data, kvdb_names, clean_stored_kvdb):
    '''
    description: Check that KVDBs can't be created using invalid input files.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Verify that given output command is the correct one.
        - Verify that no db was created.

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

    assertions:
        - Check that the engine output is the expected.
        - Check that the database was not created.

    input_description:
        - The `cases_kvdb_api_database_creation_using_invalid_file_format` file provides the test cases.

    expected_output:
        - r".* An error occurred while parsing the JSON file .*"
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that the create command prompt that the given kvdb already exists
    assert "An error occurred while parsing the JSON file" in processes.run_local_command_returning_output(api_call)

    # Verify that no db was created
    assert kvdb_names[0] not in engine.get_available_kvdbs(), f"The {kvdb_names[0]} database was created when " \
                                                              "it should not."
