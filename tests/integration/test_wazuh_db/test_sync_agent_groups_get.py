'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the sync-agent-groups-get command used to allow the cluster getting the
       information to be synchronized..
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
import yaml
import time
import pytest
import json


from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import (query_wdb, insert_agent_into_group, clean_agents_from_db,
                                    clean_groups_from_db, clean_belongs)
from wazuh_testing.modules import TIER0, SERVER, LINUX
from wazuh_testing.tools.file import get_list_of_content_yml

# Marks
pytestmark = [LINUX, TIER0, SERVER]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_file = os.path.join(os.path.join(test_data_path, 'global'), 'sync_agent_groups_get.yaml')
module_tests = get_list_of_content_yml(messages_file)

log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets = None  # Set in the fixtures



import socket
import struct
import json
import hashlib



def send_msg(msg):

    ADDR = '/var/ossec/queue/db/wdb'
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ADDR)
    msg = struct.pack('<I', len(msg)) + msg.encode()

    # Send msg
    sock.send(msg)

    # Receive response
    data = sock.recv(4)
    data_size = struct.unpack("<I", data[0:4])[0]
    data = sock.recv(data_size).decode(encoding="utf-8", errors="ignore").split(" ", 1)
    
    sock.close()
    return data


def get_global_hash():
    GET_GROUP_HASH = 'global sql SELECT group_hash FROM agent WHERE id > 0 AND group_hash IS NOT NULL ORDER BY id ' \
                     'LIMIT {limit} OFFSET {offset}'
    limit = 1000
    offset = 0
    group_hashes = []

    while True:
        result = send_msg(GET_GROUP_HASH.format(limit=1000, offset=offset))
        if result[1] == '[]':
            break
        offset += limit
        group_hashes.extend([item['group_hash'] for item in json.loads(result[1])])

    actual_hash = hashlib.sha1("".join(group_hashes).encode()).hexdigest()
    print(f'Global groups hash: {actual_hash}')

    return actual_hash



# Fixtures

# Insert agents into DB  and assign them into a group
@pytest.fixture(scope='function')
def pre_insert_agents_into_group():
    insert_agent_into_group(2)

    yield
    clean_agents_from_db()
    clean_groups_from_db()
    clean_belongs()


# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_sync_agent_groups(configure_sockets_environment, connect_to_sockets_module,
                           test_case, pre_insert_agents_into_group):
    '''
    description: Check that commands about sync_aget_groups_get works properly.
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
        - pre_insert_agents_into_group:
            type: fixture
            brief: fixture in charge of insert agents and groups into DB.
    assertions:
        - Verify that the socket response matches the expected output.
    input_description:
        - Test cases are defined in the sync_agent_groups_get.yaml file.
    expected_output:
        - an array with all the agents that match with the search criteria
    tags:
        - wazuh_db
        - wdb_socket
    '''
    # Set each case
    case_data = test_case[0]
    output = case_data["output"]

    # Check if it requires any special configuration
    if 'pre_input' in case_data:
        for command in case_data['pre_input']:
            query_wdb(command)

    if '[GLOBAL_HASH]' in output:
        actual_hash = get_global_hash()
        output = output.replace('[GLOBAL_HASH]', actual_hash) 

    time.sleep(1)
    response = query_wdb(case_data["input"])

    # Validate response
    assert str(response) == output, "Did not get expected response: {output}, recieved: {response}"

    # Validate if the status of the group has change
    if "new_status" in case_data:
        agent_id = json.loads(case_data["agent_id"])
        for id in agent_id:
            response = query_wdb(f'global get-agent-info {id}')
            assert case_data["new_status"] == response[0]['group_sync_status']
