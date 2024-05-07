# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from modules.testing.utils import logger
from ..helpers.generic import HostInformation, GeneralComponentActions
from ..helpers.manager import WazuhManager
from ..helpers.dashboard import WazuhDashboard
from ..helpers.indexer import WazuhIndexer


@pytest.fixture(scope="module", autouse=True)
def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')
    targets = request.config.getoption('--targets')

    params = {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': dependencies,
        'targets': targets
    }
    yield params
    logger.info('Restoring Wazuh central components statuses')
    GeneralComponentActions.component_restart(params['master'], 'wazuh-manager')

    for indexer_params in params['indexers']:
        GeneralComponentActions.component_restart(indexer_params, 'wazuh-indexer')

    GeneralComponentActions.component_restart(params['dashboard'], 'wazuh-dashboard')
    GeneralComponentActions.component_restart(params['master'], 'filebeat')


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

def test_stop(wazuh_params):
    GeneralComponentActions.component_stop(wazuh_params['master'], 'wazuh-manager')

    for indexer_params in wazuh_params['indexers']:
        GeneralComponentActions.component_stop(indexer_params, 'wazuh-indexer')

    GeneralComponentActions.component_stop(wazuh_params['dashboard'], 'wazuh-dashboard')
    GeneralComponentActions.component_stop(wazuh_params['master'], 'filebeat')

def test_manager_status(wazuh_params):
    assert 'inactive' in GeneralComponentActions.get_component_status(wazuh_params['master'], 'wazuh-manager'), logger.error(f"The Wazuh manager in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is not active")


def test_dashboard_status(wazuh_params):
    assert 'inactive' in GeneralComponentActions.get_component_status(wazuh_params['dashboard'], 'wazuh-dashboard'), logger.error(f"The Wazuh dashboard in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['dashboard'])} is not active")


def test_indexer_status(wazuh_params):
    for indexer_params in wazuh_params['indexers']:
        assert 'inactive' in GeneralComponentActions.get_component_status(indexer_params, 'wazuh-indexer'), logger.error(f'The Wazuh indexer in {HostInformation.get_os_name_and_version_from_inventory(indexer_params)} is not active')


def test_filebeat_status(wazuh_params):
    assert 'inactive' in GeneralComponentActions.get_component_status(wazuh_params['master'], 'filebeat'), logger.error(f"The Filebeat in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is not active")


def test_manager_api_port(wazuh_params):
    assert not WazuhManager.is_wazuh_api_port_open(wazuh_params['master'], cycles=1, wait=1), logger.error(f"The Wazuh manager API port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is still active")


def test_manager_agent_port(wazuh_params):
    assert not WazuhManager.is_wazuh_agent_port_open(wazuh_params['master'], cycles=1, wait=1), logger.error(f"The Wazuh manager port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is still active")


def test_manager_agent_enrollment_port(wazuh_params):
    assert not WazuhManager.is_wazuh_agent_enrollment_port_open(wazuh_params['master'], cycles=1, wait=1), logger.error(f"The Wazuh manager agent enrollment port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['master'])} is still active")


def test_dashboard_port(wazuh_params):
    assert not WazuhDashboard.is_dashboard_port_open(wazuh_params['dashboard'], cycles=1, wait=1), logger.error(f"The Wazuh dashboard port in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params['dashboard'])} is still active")


def test_indexer_port(wazuh_params):
    for indexer_params in wazuh_params['indexers']:
        assert not WazuhIndexer.is_indexer_port_open(indexer_params, cycles=1, wait=1), logger.error(f"Some Wazuh indexer port in {HostInformation.get_os_name_and_version_from_inventory(indexer_params)} is still active")
