# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import re

from ..helpers.agent import WazuhAgent, WazuhAPI
from ..helpers.generic import GeneralComponentActions, HostInformation
from ..helpers.logger.logger import logger
from ..helpers.manager import WazuhManager
from ..helpers.utils import Utils

@pytest.fixture(scope="module", autouse=True)
def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')
    targets = request.config.getoption('--targets')
    live = request.config.getoption('--live')

    return {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': dependencies,
        'targets': targets,
        'live': live
    }


@pytest.fixture(scope="module", autouse=True)
def setup_test_environment(wazuh_params):
    targets = wazuh_params['targets']
    # Clean the string and split it into key-value pairs
    targets = targets.replace(' ', '')
    targets = targets.replace('  ', '')
    pairs = [pair.strip() for pair in targets.strip('{}').split(',')]
    targets_dict = dict(pair.split(':') for pair in pairs)

    wazuh_params['master'] = targets_dict.get('wazuh-1')
    wazuh_params['workers'] = [value for key, value in targets_dict.items() if key.startswith('wazuh-') and key != 'wazuh-1']
    wazuh_params['agents'] = [value for key, value in targets_dict.items() if key.startswith('agent')]
    wazuh_params['indexers'] = [value for key, value in targets_dict.items() if key.startswith('node-')]
    wazuh_params['dashboard'] = targets_dict.get('dashboard', wazuh_params['master'])

    # If there are no indexers, we choose wazuh-1 by default
    if not wazuh_params['indexers']:
        wazuh_params['indexers'].append(wazuh_params['master'])

    wazuh_params['managers'] = {key: value for key, value in targets_dict.items() if key.startswith('wazuh-')}
    wazuh_params['agents'] = {key + '-' + re.findall(r'agent-(.*?)/', value)[0].replace('.',''): value for key, value in targets_dict.items() if key.startswith('agent')}

    updated_agents = {}
    for agent_name, agent_params in wazuh_params['agents'].items():
        Utils.check_inventory_connection(agent_params)
        if GeneralComponentActions.isComponentActive(agent_params, 'wazuh-agent') and GeneralComponentActions.hasAgentClientKeys(agent_params):
            if HostInformation.get_client_keys(agent_params) != []:
                client_name = HostInformation.get_client_keys(agent_params)[0]['name']
                updated_agents[client_name] = agent_params
            else:
                updated_agents[agent_name] = agent_params
        if updated_agents != {}:
            wazuh_params['agents'] = updated_agents

def test_restart(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        GeneralComponentActions.component_restart(agent_params, 'wazuh-agent')


def test_status(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert 'active' in GeneralComponentActions.get_component_status(agent_params, 'wazuh-agent'), logger.error(f'{agent_names} is not active by command')


def test_connection(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert agent_names in WazuhManager.get_agent_control_info(wazuh_params['master']), logger.error(f'{agent_names} is not present in agent_control information')


def test_isActive(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert GeneralComponentActions.isComponentActive(agent_params, 'wazuh-agent'), logger.error(f'{agent_names} is not active by command')


def test_clientKeys(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert GeneralComponentActions.hasAgentClientKeys(agent_params), logger.error(f'{agent_names} has not ClientKeys file')


def test_port(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert WazuhAgent.isAgent_port_open(agent_params), logger.error('Port is closed')


def test_processes(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert WazuhAgent.areAgent_processes_active(agent_params), logger.error('Agent processes are not active')
