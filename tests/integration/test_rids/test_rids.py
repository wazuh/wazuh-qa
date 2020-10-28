# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import sqlite3
import time
import psutil


from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector, Agent, \
                    create_agents
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import SocketController
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

RIDS_DIR = os.path.join(WAZUH_PATH, 'queue', 'rids')

SERVER_ADDRESS = 'localhost'
CRYPTO = 'aes'
PROTOCOL = 'tcp'


metadata = [
    {
        'agents_number': 1,
        'check_close': [False]
    },
    {
        'agents_number': 1,
        'check_close': [True]
    },
    {
        'agents_number': 3,
        'check_close': [True, True, True]
    },
    {
        'agents_number': 3,
        'check_close': [False, False, False]
    },
    {
        'agents_number': 3,
        'check_close': [True, False, True]
    }
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
    set_recv_counter_flush(10)
    control_service('restart')

    yield


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


def get_remoted_pid():
    for process in psutil.process_iter():
        if process.name() == 'ossec-remoted':
            return process.pid
    return None


def set_recv_counter_flush(new_recv_counter):
    new_content = ''

    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line
            if 'remoted.recv_counter_flush' in line:
                new_line = f'remoted.recv_counter_flush={new_recv_counter}\n'
            new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)


def test_rids(get_configuration, configure_environment, restart_service):
    metadata = get_configuration.get('metadata')
    agents_number = metadata['agents_number']
    check_close = metadata['check_close']

    agents = create_agents(agents_number, SERVER_ADDRESS, CRYPTO)

    injectors = create_injectors(agents)

    # Let time to remoted store counters for agents
    time.sleep(20)

    process = psutil.Process(get_remoted_pid())
    opened = process.open_files()

    # Check that rids is open
    for agent in agents:
        agent_rids_path = os.path.join(RIDS_DIR, agent.id)
        rids_for_agent_open = False
        for path in opened:
            if agent_rids_path in path:
                rids_for_agent_open = True
                break

        assert rids_for_agent_open, f"Agent fd should be open {agent.id}"

    for index, injector in enumerate(injectors):
        if check_close[index]:
            injector.stop_receive()

    if True in check_close:
        # Wait that the thread close the rids
        time.sleep(120)

        opened = process.open_files()

        # Check that rids is close
        for agent_index, agent in enumerate(agents):
            agent_rids_path = os.path.join(RIDS_DIR, agents[agent_index].id)
            rids_for_agent_open = False

            for path in opened:
                if agent_rids_path in path:
                    rids_for_agent_open = True
                    break

            if check_close[agent_index]:
                assert not rids_for_agent_open, f"Agent fd should be close {agents[agent_index].id}"
            else:
                assert rids_for_agent_open, f"Agent fd should be open {agents[agent_index].id}"
                injectors[agent_index].stop_receive()
