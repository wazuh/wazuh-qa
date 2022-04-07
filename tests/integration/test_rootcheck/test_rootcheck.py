'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'rootcheck' tool allows to define policies in order to check if the agents
       meet the requirement specified. The rootcheck engine can check if a process is running, if a file is 
       present and if the content of a file contains a pattern, 
       or if a Windows registry key contains a string or is simply present.

components:
    - rootcheck

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/policy-monitoring/rootcheck
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - rootcheck
'''

import json
import os
import sqlite3
import time
import pytest

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.agent_simulator import Sender, Injector, create_agents
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import SocketController
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

WAZUH_DB_DIR = os.path.join(WAZUH_PATH, 'queue', 'db')
WDB_PATH = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
ALERTS_JSON_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.json')

SERVER_ADDRESS = 'localhost'
CRYPTO = 'aes'
PROTOCOL = 'tcp'

metadata = [
    {
        'agents_number': 1,
        'check_updates': False,
        'check_delete': False
    },
    {
        'agents_number': 3,
        'check_updates': False,
        'check_delete': False
    },
    {
        'agents_number': 1,
        'check_updates': True,
        'check_delete': False
    },
    {
        'agents_number': 3,
        'check_updates': True,
        'check_delete': False
    },
    {
        'agents_number': 1,
        'check_updates': False,
        'check_delete': True
    },
    {
        'agents_number': 3,
        'check_updates': False,
        'check_delete': True
    },
]
params = [{} for x in range(0, len(metadata))]

ids = [f"check_updates:{x['check_updates']}, check_delete:{x['check_delete']}, {x['agents_number']}_agents"
       for x in metadata]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params, metadata=metadata)


@pytest.fixture(scope="module", params=configurations, ids=ids)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope="function")
def restart_service():
    control_service('restart')

    yield


@pytest.fixture(scope="function")
def clean_alert_logs():
    truncate_file(ALERTS_JSON_PATH)


def retrieve_rootcheck_rows(agent_id):
    agent_db_path = os.path.join(WAZUH_DB_DIR, f'{agent_id}.db')
    conn = sqlite3.connect(agent_db_path)
    cursor = conn.cursor()
    cursor.execute("select * from pm_event")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def create_injectors(agents):
    injectors = []
    sender = Sender(SERVER_ADDRESS, protocol=PROTOCOL)
    for index, agent in enumerate(agents):
        injector = Injector(sender, agent)
        injectors.append(injector)
        injector.run()
        if PROTOCOL == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=PROTOCOL)
    return injectors


def send_delete_table_request(agent_id):
    controller = SocketController(WDB_PATH)
    controller.send(f'agent {agent_id} rootcheck delete', size=True)
    response = controller.receive(size=True)
    return response


def test_rootcheck(get_configuration, configure_environment, restart_service,
                   clean_alert_logs):
    '''
    description: Check if the 'rootcheck' modules is working properly, that is, by checking if the created logs
                 are added, updated and deleted correctly.
                 For this purpose, the test will create a specific number of agents, and will check if they have
                 the rootcheck module enabled. Once this check is proven, it lets the rootcheck events to be sent
                 for 60 seconds. After the time has passed, the rootcheck module gets disabled and the test then
                 checks if the logs have been added to the database. After this first procedure, the test restarts
                 the service and let the rootcheck events to be sent for 60 seconds for checking after that time if
                 the logs have been updated with the new entries.
                 Lastly, the tests also checks if the logs are deleted from the database when sending the delete
                 table request.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_service:
            type: fixture
            brief: restart the services
        - clean_alert_logs:
            - type: fixture
            - brief: reset the content of the alert logs
    assertions:
        - Verify that rootcheck events are added into the database
        - Verify that the rootcheck events are updated on the database
        - Verify that the rootcheck events are deletet from the database
    input_description: Different test cases are contained in an external YAML file (wazuh_manager_conf.yaml)
                       which includes configuration settings for the 'rootcheck' module.
    expected_output:
        - r'.*not found in Database'
        - r'.*not found in alerts file'
        - r'.*not found in Database'
        - First time in log was updated after insertion
        - Updated time in log was not updated
        - Wazuh DB returned an error trying to delete the agent
        - Rootcheck events were not deleted

    tags:
        - rootcheck
    '''
    metadata = get_configuration.get('metadata')
    agents_number = metadata['agents_number']
    check_updates = metadata['check_updates']
    check_delete = metadata['check_delete']

    agents = create_agents(agents_number, SERVER_ADDRESS, CRYPTO)

    for agent in agents:
        agent.modules['rootcheck']['status'] = 'enabled'

    injectors = create_injectors(agents)

    # Let rootcheck events to be sent for 60 seconds
    time.sleep(60)

    for injector in injectors:
        injector.stop_receive()

    # Service needs to be stopped otherwise db lock will be held by Wazuh db
    control_service('stop')

    # Check that logs have been added to the sql database
    for agent in agents:
        rows = retrieve_rootcheck_rows(agent.id)
        db_string = [row[3] for row in rows]

        logs_string = [':'.join(x.split(':')[2:]) for x in
                       agent.rootcheck.messages_list]
        for log in logs_string:
            assert log in db_string, f"Log: \"{log}\" not found in Database"

        alerts_description = None
        with open(ALERTS_JSON_PATH, 'r') as f:
            json_lines = [json.loads(x) for x in f.readlines()]
            alerts_description = [x['full_log'] for x in json_lines
                                  if 'rootcheck' in x['decoder']['name']]
            for log in logs_string:
                if log not in ['Starting rootcheck scan.',
                               'Ending rootcheck scan.']:
                    assert log in alerts_description, f"Log: \"{log}\" " \
                                                      "not found in alerts file"

    if check_updates:
        # Service needs to be restarted
        control_service('start')

        update_threshold = time.time()

        injectors = create_injectors(agents)

        # Let rootcheck events to be sent for 60 seconds
        time.sleep(60)

        for injector in injectors:
            injector.stop_receive()

        # Service needs to be stopped otherwise db lock will be held by Wazuh db
        control_service('stop')

        # Check that logs have been updated
        for agent in agents:
            rows = retrieve_rootcheck_rows(agent.id)

            logs_string = [':'.join(x.split(':')[2:]) for x in
                           agent.rootcheck.messages_list]
            for row in rows:
                assert row[1] < update_threshold, \
                    f'First time in log was updated after insertion'
                assert row[2] > update_threshold, \
                    f'Updated time in log was not updated'
                assert row[3] in logs_string, \
                    f"Log: \"{log}\" not found in Database"

    if check_delete:
        # Service needs to be restarted
        control_service('start')

        for agent in agents:
            response = send_delete_table_request(agent.id)
            assert response.startswith(b'ok'), "Wazuh DB returned an error " \
                                               "trying to delete the agent"

        # Wait 5 seconds
        time.sleep(5)

        # Service needs to be stopped otherwise db lock will be held by Wazuh db
        control_service('stop')

        # Check that logs have been deleted
        for agent in agents:
            rows = retrieve_rootcheck_rows(agent.id)
            assert len(rows) == 0, 'Rootcheck events were not deleted'
