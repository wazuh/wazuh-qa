# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from modules.testing.utils import logger
from ..helpers.constants import WAZUH_ROOT
from ..helpers.generic import HostInformation, GeneralComponentActions
from ..helpers.manager import WazuhManager
from ..helpers.dashboard import WazuhDashboard
from ..helpers.indexer import WazuhIndexer
from ..helpers.central import WazuhCentralComponents


@pytest.fixture(scope="module", autouse=True)
def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')
    targets = request.config.getoption('--targets')

    return {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': dependencies,
        'targets': targets
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
    wazuh_params['indexers'] = [value for key, value in targets_dict.items() if key.startswith('node-')]
    wazuh_params['dashboard'] = targets_dict.get('dashboard', wazuh_params['master'])

    # If there are no indexers, we choose wazuh-1 by default
    if not wazuh_params['indexers']:
        wazuh_params['indexers'].append(wazuh_params['master'])

    wazuh_params['managers'] = {key: value for key, value in targets_dict.items() if key.startswith('wazuh-')}


def test_uninstall(wazuh_params):
    assert 'active' in GeneralComponentActions.get_component_status(wazuh_params['master'], 'wazuh-manager'), logger.error(f'The manager in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["master"])} is not active')
    assert 'active' in GeneralComponentActions.get_component_status(wazuh_params['dashboard'], 'wazuh-dashboard'), logger.error(f'The dashboard in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["dashboard"])} is not active')
    for indexer_params in wazuh_params['indexers']:
        assert 'active' in GeneralComponentActions.get_component_status(indexer_params, 'wazuh-indexer'), logger.error(f'The indexer in {HostInformation.get_os_name_and_version_from_inventory(indexer_params)} is not active')
    assert 'active' in GeneralComponentActions.get_component_status(wazuh_params['master'], 'filebeat'), logger.error(f'The filebeat in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["master"])} is not active')

    WazuhCentralComponents.uninstall_aio(wazuh_params['master'])

def test_component_uninstalled_directory(wazuh_params):
    assert not HostInformation.dir_exists(wazuh_params['master'], WAZUH_ROOT), logger.error(f"In {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} {WAZUH_ROOT} is still present")


def test_manager_api_port(wazuh_params):
    assert not WazuhManager.is_wazuh_api_port_open(wazuh_params['master'], cycles=1, wait=1), logger.error(f"The Wazuh manager API port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is still active")


def test_manager_agent_port(wazuh_params):
    assert not WazuhManager.is_wazuh_agent_port_open(wazuh_params['master'], cycles=1, wait=1), logger.error(f"The Wazuh manager API port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is still active")


def test_manager_agent_enrollment_port(wazuh_params):
    assert not WazuhManager.is_wazuh_agent_enrollment_port_open(wazuh_params['master'], cycles=1, wait=1), logger.error(f"The Wazuh manager API port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is still active")


def test_dashboard_port(wazuh_params):
    assert not WazuhDashboard.is_dashboard_port_open(wazuh_params['dashboard'], cycles=1, wait=1), logger.error(f"The Wazuh dashboard port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['dashboard'])} is still active")


def test_indexer_port(wazuh_params):
    for indexer_params in wazuh_params['indexers']:
        assert not WazuhIndexer.is_indexer_port_open(indexer_params, cycles=1, wait=1), logger.error(f"Some Wazuh indexer port in {HostInformation.get_os_name_and_version_from_inventory(indexer_params)} is still active")
