
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import sqlite3
import time


from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector, Agent, \
                    create_agents
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

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params, metadata=metadata)


@pytest.fixture(scope="module", params=configurations)
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
    metadata = get_configuration.get('metadata')
    agents_number = metadata['agents_number']
    check_updates = metadata['check_updates']
    check_delete = metadata['check_delete']

    agents = create_agents(agents_number, SERVER_ADDRESS, CRYPTO)

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
                       agent.rootcheck.rootcheck]
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
        # Service needs to be stopped otherwise db lock will be held by
        # Wazuh db
        control_service('start')

        update_threshold = time.time()

        create_injectors(agents)

        # Let rootcheck events to be sent for 60 seconds
        time.sleep(60)

        # Check that logs have been updated
        for agent in agents:
            rows = retrieve_rootcheck_rows(agent.id)

            logs_string = [':'.join(x.split(':')[2:]) for x in
                           agent.rootcheck.rootcheck]
            for row in rows:
                assert row[1] < update_threshold, \
                    f'First time in log was updated after insertion'
                assert row[2] > update_threshold, \
                    f'Updated time in log was not updated'
                assert row[3] in logs_string, \
                    f"Log: \"{log}\" not found in Database"

    if check_delete:
        # Service needs to be stopped otherwise db lock will be held by
        # Wazuh db
        control_service('start')

        for agent in agents:
            response = send_delete_table_request(agent.id)
            assert response.startswith(b'ok'), "Wazuh DB returned an error " \
                "trying to delete the agent"

            rows = retrieve_rootcheck_rows(agent.id)
            assert len(rows) == 0, 'Rootcheck events were not deleted'
