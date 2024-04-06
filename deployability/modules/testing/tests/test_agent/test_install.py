# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import re

from ..helpers.agent import WazuhAgent
from ..helpers.constants import WAZUH_ROOT
from ..helpers.generic import HostConfiguration, HostInformation, GeneralComponentActions
from ..helpers.logger.logger import logger
from ..helpers.manager import WazuhManager
from ..helpers.utils import Utils


@pytest.fixture
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


@pytest.fixture(autouse=True)
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
        if GeneralComponentActions.isComponentActive(agent_params, 'wazuh-agent') and GeneralComponentActions.hasAgentClientKeys(agent_params):
            if HostInformation.get_client_keys(agent_params) != []:
                client_name = HostInformation.get_client_keys(agent_params)[0]['name']
                updated_agents[client_name] = agent_params
            else:
                updated_agents[agent_name] = agent_params
        if updated_agents != {}:
            wazuh_params['agents'] = updated_agents

def test_installation(wazuh_params):
    # Checking connection
    for manager_name, manager_params in wazuh_params['managers'].items():
        Utils.check_inventory_connection(manager_params)

    # Certs creation, firewall management and Manager installation
    for agent_name, agent_params in wazuh_params['agents'].items():
        HostConfiguration.disable_firewall(agent_params)

    if HostInformation.dir_exists(wazuh_params['master'], WAZUH_ROOT):
        logger.info(f'Manager is already installed in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["master"])}')
    else:
        HostConfiguration.disable_firewall(manager_params)
        HostConfiguration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'])
        WazuhManager.install_manager(wazuh_params['master'], 'wazuh-1', wazuh_params['wazuh_version'])
    assert HostInformation.dir_exists(wazuh_params['master'], WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is not present in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["master"])}')

    # Agent installation
    for agent_names, agent_params in wazuh_params['agents'].items():
        WazuhAgent.perform_install_and_scan_for_agent(agent_params, agent_names, wazuh_params)

    # Testing installation directory
    for agent in wazuh_params['agents'].values():
        assert HostInformation.dir_exists(agent, WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is not present in {HostInformation.get_os_name_and_version_from_inventory(agent)}')


def test_status(wazuh_params):
    for agent in wazuh_params['agents'].values():
        agent_status = GeneralComponentActions.get_component_status(agent, 'wazuh-agent')
        assert 'loaded' in agent_status, logger.error(f'The {HostInformation.get_os_name_and_version_from_inventory(agent)} status is not loaded')


def test_version(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert wazuh_params['wazuh_version'] in GeneralComponentActions.get_component_version(agent_params), logger.error(f"The version {HostInformation.get_os_name_and_version_from_inventory(agent_params)} is not {wazuh_params['wazuh_version']} by command")


def test_revision(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert wazuh_params['wazuh_revision'] in GeneralComponentActions.get_component_revision(agent_params), logger.error(f"The revision {HostInformation.get_os_name_and_version_from_inventory(agent_params)} is not {wazuh_params['wazuh_revision']} by command")
