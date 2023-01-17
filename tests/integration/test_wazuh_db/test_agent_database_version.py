'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks that the agent database version is the expected.

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
from time import sleep

from wazuh_testing import DB_PATH, T_5
from wazuh_testing.modules import TIER0, LINUX, SERVER
from wazuh_testing.db_interface import get_sqlite_query_result
from wazuh_testing.wazuh_db import query_wdb

# Marks
pytestmark = [TIER0, LINUX, SERVER]


# Configurations



# Variables



# Fixtures


# Tests
def test_agent_database_version():
    '''
    description: Check that the agent database version is the expected one. To do this, it performs a query to the agent
                 database that gets the database version.

    wazuh_min_version: 4.4.0

    parameters:

    assertions:
        - Verify that database version is the expected one.

    input_description:

    expected_output:
        - Database version: 10

    tags:
        - wazuh_db
        - wdb_socket
    '''
    version = get_sqlite_query_result(os.path.join(DB_PATH, '000.db'),
                                      "SELECT value FROM metadata WHERE key='db_version'")
    # Wait for wazuh-db to start and create the wdb socket
    sleep(T_5)
    version2 = query_wdb("agent 0 sql SELECT value FROM metadata WHERE key='db_version'")

    assert version[0] == version2[0]['value'] == '10'
