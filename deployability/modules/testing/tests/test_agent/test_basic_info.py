# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import pytest

from modules.testing.utils import logger
from ..helpers.agent import WazuhAgent, WazuhAPI, get_agent_from_inventory
from ..helpers.constants import WAZUH_ROOT, WINDOWS_ROOT_DIR, MACOS_ROOT_DIR
from ..helpers.generic import HostInformation, GeneralComponentActions, Waits
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
        if GeneralComponentActions.is_component_active(agent_params, 'wazuh-agent') and GeneralComponentActions.has_agent_client_keys(agent_params):
            if HostInformation.get_client_keys(agent_params) != []:
                client_name = HostInformation.get_client_keys(agent_params)[0]['name']
                updated_agents[client_name] = agent_params
            else:
                updated_agents[agent_name] = agent_params
        if updated_agents != {}:
            wazuh_params['agents'] = updated_agents


def test_wazuh_os_version(wazuh_params):
    wazuh_api = WazuhAPI(wazuh_params['master'])
    for agent_names, agent_params in wazuh_params['agents'].items():
        path_to_check = ''
        os_type = HostInformation.get_os_type(agent_params)

        if os_type == 'linux':
            path_to_check = WAZUH_ROOT
        elif os_type == 'windows':
            path_to_check = WINDOWS_ROOT_DIR
        elif os_type == 'macos':
            path_to_check = MACOS_ROOT_DIR

        assert HostInformation.dir_exists(agent_params, path_to_check), logger.error(f'The {path_to_check} is not present in {HostInformation.get_os_name_and_version_from_inventory(agent_params)}')

        expected_condition_func = lambda: 'active' == WazuhAgent.get_agent_status(wazuh_api, agent_names)
        Waits.dynamic_wait(expected_condition_func, cycles=20, waiting_time=30)

        agent = get_agent_from_inventory(agent_params)
        agent_version = agent.get_os_version()
        agent_api_version = WazuhAgent.get_agent_os_version_by_name(wazuh_api, agent_names)
        logger.debug(f"Version obtained from agent: {agent_version}")
        logger.debug(f"Version obtained from Wazuh API: {agent_api_version}")
        assert agent_version in agent_api_version, logger.error('There is a mismatch between the OS version and the OS version of the installed agent')

        if os_type == 'macos':
            os_name = 'macos'
        elif os_type == 'windows':
            os_name = 'windows'
        elif os_type == 'linux':
            os_name = HostInformation.get_os_name_from_inventory(agent_params)

        assert os_name in WazuhAgent.get_agent_os_name_by_name(wazuh_api, agent_names).replace(' ', ''),  logger.error('There is a mismatch between the OS name and the OS name of the installed agent')

def test_wazuh_version(wazuh_params):
    for _, agent_params in wazuh_params['agents'].items():
        assert wazuh_params['wazuh_version'] in GeneralComponentActions.get_component_version(agent_params), logger.error(f"The version {HostInformation.get_os_name_and_version_from_inventory(agent_params)} is not {wazuh_params['wazuh_version']} by command")


def test_wazuh_revision(wazuh_params):
    for _, agent_params in wazuh_params['agents'].items():
        assert wazuh_params['wazuh_revision'] in GeneralComponentActions.get_component_revision(agent_params), logger.error(f"The revision {HostInformation.get_os_name_and_version_from_inventory(agent_params)} is not {wazuh_params['wazuh_revision']} by command")
