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
import json
import pytest

from wazuh_testing import processes
from wazuh_testing.modules import engine
from wazuh_testing.tools.configuration import get_test_cases_data

# Reference paths
TEST_KVDBS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'data', 'kvdbs')
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_database_content_dump.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_kvdb_api_non_existent_database_content_dump.yaml')

# Engine events configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)

# Variables related to api calls and kvdbs
t1_api_call_data = engine.get_api_call_data(t1_configuration_metadata)
t1_kvdb_names = engine.get_kvdb_names(t1_configuration_metadata)
t2_kvdb_names = engine.get_kvdb_names(t2_configuration_metadata)
t2_api_call_data = engine.get_api_call_data(t2_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t1_api_call_data, t1_kvdb_names), ids=t1_case_ids)
def test_kvdb_dump_db_content(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that the engine can show the databases content as expected.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Request to the API the dump call.
        - Verify that the db content is the expected from the JSON input file.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - api_call_data:
            type: dict
            brief: Data from the cases required to build the API calls.
        - kvdb_names:
            type: str
            brief: Database name to be created.
        - clean_all_stored_kvdb:
            type: fixture
            brief: Clean all the KVDBs from memory.
        - create_predefined_kvdb:
            type: fixture
            brief: Create the KVDBs provided within the kvdb_names variable.

    assertions:
        - Check that DB content is the expected.

    input_description:
        - The `cases_kvdb_api_database_content_dump` file provides the test cases.

    expected_output:
        - List of pairs that the db contains.
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that given output is the expected: list of pairs
    assert processes.run_local_command_returning_output(api_call) == \
        f"{json.dumps(engine.get_kvdb_content(db_name=kvdb_names[0], engine_format=True), separators=(',', ':'))}\n"


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data', t1_api_call_data, ids=t1_case_ids)
def test_kvdb_dump_non_existent_db(api_call_data, clean_all_stored_kvdb):
    '''
    description: Check that the engine can't show the content of a non-existent database when there are no databases
                 in memory.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Request to the API the dump call.
        - Verify that the dump output is the expected: That db is not loaded.

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
        - Check that dump output is the expected.

    input_description:
        - The `cases_kvdb_api_database_content_dump` file provides the test cases.

    expected_output:
        - r"Database '.*' not found or could not be loaded."
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that the content can't be shown because the db does not exist
    assert processes.run_local_command_returning_output(api_call) == f"Database '{api_call_data['options']['-n']}' " \
                                                                     "not found or could not be loaded\n"


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('api_call_data, kvdb_names', zip(t2_api_call_data, t2_kvdb_names), ids=t2_case_ids)
def test_kvdb_dump_non_existent_db_no_loaded_dbs(api_call_data, kvdb_names, clean_stored_kvdb, create_predefined_kvdb):
    '''
    description: Check that the engine can't show the databases content when that db is not within the loaded ones.

    test_phases:
        - Delete the KVDBs that could be in the environment.
        - Request to the API the dump call.
        - Verify that the db content is the expected from the JSON input file.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - api_call_data:
            type: dict
            brief: Data from the cases required to build the API calls.
        - kvdb_names:
            type: str
            brief: Database name to be created.
        - clean_all_stored_kvdb:
            type: fixture
            brief: Clean all the KVDBs from memory.
        - create_predefined_kvdb:
            type: fixture
            brief: Create the KVDBs provided within the kvdb_names variable.

    assertions:
        - Check that DB content is the expected.

    input_description:
        - The `cases_kvdb_api_non_existent_database_content_dump` file provides the test cases.

    expected_output:
        - r"Database '.*' not found or could not be loaded."
    '''
    # Create api call that uses the call data for that Tcase
    api_call = engine.create_api_call(api_call_data['command'], api_call_data['subcommand'],
                                      api_call_data['options'] if 'options' in api_call_data else {})

    # Verify that the content can't be shown because the db does not exist
    assert processes.run_local_command_returning_output(api_call) == f"Database '{api_call_data['options']['-n']}' " \
                                                                     "not found or could not be loaded\n"
