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
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_delete.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_delete_not_loaded.yaml')

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
def test_kvdb_delete_databases(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that KVDBs can be created as expected using a JSON file as input.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Create the provided KVDBs.
        - Verify the created databases' content in memory.

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
        - Check that engine's output is the expected.
        - Check that the kvdb has been deleted from memory.

    input_description:
        - The `cases_kvdb_api_database_creation` file provides the test cases.

    expected_output:
        - r"KVDB '.*' successfully deleted\n"
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that the created kvdb has the expected pairs
    assert processes.run_local_command_returning_output(api_call) == f"KVDB '{kvdb_names[0]}' successfully deleted\n", \
        'The API call was not received as expected.'

    # Verify that the deleted kvdb is in memory no longer
    assert kvdb_names[0] not in engine.get_available_kvdbs(), f"The {kvdb_names[0]} database was not deleted."


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data', t1_api_call_data, ids=t1_case_ids)
def test_kvdb_delete_with_no_dbs(api_call_data, clean_all_stored_kvdb):
    '''
    description: Check that KVDBs can be created as expected using a JSON file as input.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Try to delete the dbs without being created.
        - Verify that dbs were not created.

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
        - Check that no databases are in memory.
        - Check that engine's output is the expected.
        - Check that there are no kvdbs when trying to delete.

    input_description:
        - The `cases_kvdb_api_database_creation` file provides the test cases.

    expected_output:
        - r"Database .* not found or could not be loaded"
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that there are no kvdbs in memory
    assert not engine.get_available_kvdbs(), 'There are databases in memory when it should not.'

    # Verify that the kvdb can't be deleted as it has not been loaded
    assert 'not found or could not be loaded' in \
           processes.run_local_command_returning_output(api_call), 'The API call was not received as expected.'

    # Verify that still no kvdb in memory
    assert not engine.get_available_kvdbs(), 'Some database has been created when it should not.'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t2_api_call_data, t2_kvdb_names), ids=t2_case_ids)
def test_kvdb_delete_databases_not_loaded(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that KVDBs can be created as expected using a JSON file as input.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Verify that the db that gonna be deleted is not in memory.
        - Delete the dbs.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - api_call_data:
            type: dict
            brief: Data from the cases required to build the API calls.
        - clean_all_stored_kvdb:
            type: fixture
            brief: Clean all the KVDBs from memory.
        - create_predefined_kvdb:
            type: fixture
            brief: Create the KVDBs provided within the kvdb_names variable.

    assertions:
        - Check that the database to delete is not in memory.
        - Check that engine's output is the expected.

    input_description:
        - The `cases_kvdb_api_database_creation` file provides the test cases.

    expected_output:
        - r"Database .* not found or could not be loaded"
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that the database is not in memory
    assert api_call_data['options']['-n'] not in engine.get_available_kvdbs(), f"The {api_call_data['options']['-n']}" \
                                                                               " database was not deleted."

    # Verify that the kvdb can't be deleted as it has not been loaded
    assert 'not found or could not be loaded' in \
           processes.run_local_command_returning_output(api_call), 'The API call was not received as expected.'
