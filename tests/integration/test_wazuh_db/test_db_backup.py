'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the get-groups-integrity command used to determine if the agent groups are synced 
       or if a sync is needed.

tier: 0

modules:
    - wazuh_db

components:
    - manager

daemons:
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''
import os
import time
import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools.file import recursive_directory_creation, remove_file

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_file = os.path.join(os.path.join(test_data_path, 'global'), 'wazuh_db_backup_command.yaml')
module_tests = []
with open(messages_file) as f:
    module_tests.append((yaml.safe_load(f), messages_file.split('_')[0]))

log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
backups_path = os.path.join(WAZUH_PATH, 'backup', 'db')
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets= None  # Set in the fixtures


# Variables
test_values = ["test_key1", "test_value1"]
create_db_command = 'global backup create'
get_backups_command = 'global backup get'
sql_select_command = ' global sql select * from metadata'

# Fixtures
@pytest.fixture(scope='function')
def add_database_values(request):
    "Add test values to database"
    response= query_wdb(f'global sql insert into metadata (key,value) VALUES ("{test_values[0]}","{test_values[1]}")')
    yield
    response = query_wdb(f'global sql delete from metadata where key="{test_values[0]}"')


@pytest.fixture(scope='function')
def remove_backups(request):
    "Creates backups folder in case it does not exist."
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)
    yield
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)

# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_wdb_backup_command(configure_sockets_environment, connect_to_sockets_module, remove_backups, add_database_values, test_case):
    '''
    description: Check that every input message using the 'get-groups-integrity' command in wazuh-db socket generates
                 the proper output to wazuh-db socket. To do this, it performs a query to the socket with a command
                 taken from the list of test_cases's 'input' field, and compare the result with the test_case's
                 'output' field.

    wazuh_min_version: 4.4.0

    parameters:
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - test_case:
            type: fixture
            brief: List of test_case stages (dicts with input, output and agent_id and expected_groups keys).

    assertions:
        - Verify that the socket response matches the expected output.

    input_description:
        - Test cases are defined in the get_groups_integrity_messages.yaml file. This file contains the agent id's to
          register, as well as the group_sync_status that each agent will have, as well as the expected output and 
          result for the test.

    expected_output:
        - f"Assertion Error - expected {output}, but got {response}"
        - f'Unexpected response: got {response}, but expected {output}'
        - 'Unable to add agent'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    case_data = test_case[0]
    
    # Create the database backups and assert they have been created correctly
    for backup in range(0, case_data["backups_ammount"]):
        response = query_wdb(create_db_command)
        time.sleep(1)
        assert 'global.db-backup-' in response[0], f'Backup creation failed. Got: {response}'

    # Create the database backups and assert they have been created correctly
    backups= query_wdb(get_backups_command)
    assert backups.__len__() == case_data["backups_ammount"]
    
    
    # Manage retoring the DB
    if 'restore' in case_data:
        # Assert the DB has the test_values
        db_response = query_wdb(sql_select_command)
        assert test_values[0] in db_response[-1]['key']
    
        # Remove the test_values from the DB
        query_wdb(f'global sql delete from metadata where key="{test_values[0]}"')
        db_response = query_wdb(sql_select_command)
        assert test_values[0] not in db_response[-1]['key']

        # Restore the DB - Assert command response
        save_pre_restore = case_data['save_pre_restore']
        restore_command = f'global backup restore {{"snapshot": "{backups[0]}","save_pre_restore_state": {save_pre_restore}}}'
        
        if save_pre_restore == 'none':
            restore_command = f'global backup restore {{"snapshot": "{backups[0]}"}}'    

        if 'snapshot' in case_data:
            snapshot= case_data['snapshot']
            restore_command = f'global backup restore {{"{snapshot}","save_pre_restore_state": {save_pre_restore}}}'

        response = query_wdb(restore_command)
        assert case_data['restore_response'] in response

        if 'err' in case_data['restore_response']:
            return

        # Assert the test_values have been restored into the DB
        db_response = query_wdb(sql_select_command)
        assert test_values[0] in db_response[-1]['key']
        
        if save_pre_restore == 'true':
            backups= query_wdb(get_backups_command)
            assert backups.__len__() ==  case_data["backups_ammount"] +1
            assert "-pre_restore.gz" in backups[-1]

            if 'restore_pre_restore' in case_data:
                restore_command = f'global backup restore {{"snapshot": "{backups[-1]}","save_pre_restore_state": "false"}}'
                response = query_wdb(restore_command)
                assert response == case_data['restore_response']
                
                # Check that DB is empty does not have test_values after restoring
                db_response = query_wdb(sql_select_command)
                assert test_values[0] not in db_response[-1]['key']