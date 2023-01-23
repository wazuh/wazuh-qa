'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the backup command used generate backups and restore the database using backups
       generated with this same command.

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
import yaml
import pytest

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.modules import TIER0, LINUX, SERVER
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools.file import get_list_of_content_yml


# Marks
pytestmark = [TIER0, LINUX, SERVER]


# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_file = os.path.join(os.path.join(test_data_path, 'global'), 'wazuh_db_backup_command.yaml')
module_tests = get_list_of_content_yml(messages_file)
log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
backups_path = os.path.join(WAZUH_PATH, 'backup', 'db')
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets = None  # Set in the fixtures


# Variables
test_values = ["test_key1", "test_value1"]
create_db_command = 'global backup create'
get_backups_command = 'global backup get'
sql_select_command = 'global sql select * from metadata'


# Fixtures
@pytest.fixture(scope='function')
def add_database_values(request):
    "Add test values to database"
    response = query_wdb(f'global sql insert into metadata (key,value) VALUES ("{test_values[0]}","{test_values[1]}")')
    yield
    response = query_wdb(f'global sql delete from metadata where key="{test_values[0]}"')


# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
@pytest.mark.parametrize('backups_path', [backups_path])
def test_wdb_backup_command(configure_sockets_environment, connect_to_sockets_module, remove_backups,
                            add_database_values, test_case, backups_path):
    '''
    description: Check that every input message using the 'backup' command in wazuh-db socket generates
                 the proper output to wazuh-db socket. To do this, it performs a series of queries to the socket with
                 parameters from the list of test_cases, and compare the result with the test_case's 'restore_response'
                 field, as well as checking that the files have been created and the state of the data in DB in cases
                 where the 'restore' parameter is used.

    wazuh_min_version: 4.4.0

    parameters:
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - remove_backups:
            type: fixture
            brief: Creates the folder where the backups will be stored in case it doesn't exist. It clears it when the
                   test yields.
        - add_database_values:
            type: fixture
            brief: Add values to check that the restore procedure has worked and the DB has the expected data.
        - test_case:
            type: parameter
            brief: List of test_case stages (dicts with number of backups, restore, restore_response, and other keys).
    assertions:
        - Verify that the socket response matches the expected response.
        - Verify that the backup file has been created.
        - Verify that after restoring the DB has the expected data.

    input_description:
        - Test cases are defined in the wazuh_db_backup_command.yaml file. This file contains the amount of backups to
          create, if a restore of the DB will be done, and different combinations of parameters used for the restore,
          as well as the expected responses.

    expected_output:
        - f'Backup creation failed. Got: {response}'
        - f'Error - Found {backups.__len__()} files, expected {backups_amount}'
        - f'Error expected value: key:"{test_values[0]}" was not found.'
        - f'Error found unexpected: "key":"{test_values[0]}" value.'
        - f'Did not find expected: {expected} in response: {response}'
        - f'Error - Found {backups.__len__()} files, expected {backups_amount + 1}'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    case_data = test_case[0]
    backups_amount = case_data["backups_amount"]
    # Create the database backups and assert they have been created correctly
    for backup in range(0, backups_amount):
        response = query_wdb(create_db_command)
        time.sleep(1)
        assert 'global.db-backup-' in response[0], f'Backup creation failed. Got: {response}.'

    # Check that the expected amount of database backups have been created
    backups = query_wdb(get_backups_command)
    assert backups.__len__() == backups_amount, f'Found {backups.__len__()} files, expected {backups_amount}.'

    # Manage restoring the DB
    if 'restore' in case_data:
        # Assert the DB has the test_values
        db_response = query_wdb(sql_select_command)
        assert test_values[0] in db_response[-1]['key'], f'Expected value key:"{test_values[0]}" was not found.'

        # Remove the test_values from the DB
        query_wdb(f'global sql delete from metadata where key="{test_values[0]}"')
        db_response = query_wdb(sql_select_command)
        assert test_values[0] not in db_response[-1]['key'], f'Found unexpected "key":"{test_values[0]}" value.'

        # Generate the correct restore command for test
        save_pre_restore = case_data['save_pre_restore']
        restore_command = f'global backup restore {{"snapshot": "{backups[0]}",\
                            "save_pre_restore_state": {save_pre_restore}}}'

        if save_pre_restore == 'none':
            restore_command = f'global backup restore {{"snapshot": "{backups[0]}"}}'

        if 'snapshot' in case_data:
            snapshot = case_data['snapshot']
            restore_command = f'global backup restore {{"{snapshot}","save_pre_restore_state": {save_pre_restore}}}'

        # Restore the DB - Assert command response
        expected = case_data['restore_response']
        response = query_wdb(restore_command)
        assert expected in response, f'Did not find {expected} expected value in response: {response}.'

        # Break out of test if error during restore.
        if 'err' in expected:
            return

        # Assert the test_values have been restored into the DB
        db_response = query_wdb(sql_select_command)
        assert test_values[0] in db_response[-1]['key'], f'Expected value key:"{test_values[0]}" was not found.'

        if save_pre_restore == 'true':
            backups = query_wdb(get_backups_command)
            # Check that the pre-restore state backup has been generated.
            assert backups.__len__() == backups_amount + 1, f'Found {backups.__len__()} files, \
                                                               expected {backups_amount + 1}'
            # Combine the backups list content because in 'Ubuntu' the value are not stored in order.
            combined = '\t'.join(backups)
            assert "-pre_restore.gz" in combined, f'Did not find the expected "-pre_restore.gz" file"'

            if 'restore_pre_restore' in case_data:
                restore_command = f'global backup restore {{"snapshot": "{backups[-1]}",\
                                    "save_pre_restore_state": "false"}}'
                response = query_wdb(restore_command)
                assert response == expected, f'Error restoring from pre_restore state. Response {response} '
                'does not match the expected {expected}.'

                # Check that DB is empty does not have test_values after restoring
                db_response = query_wdb(sql_select_command)
                assert test_values[0] not in db_response[-1]['key'], f'Found unexpected  \
                                                                       "key":"{test_values[0]}" value.'
