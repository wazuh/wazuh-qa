# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from ..helpers.constants import WAZUH_ROOT
from ..helpers.executor import WazuhAPI
from ..helpers.generic import HostConfiguration, HostInformation, GeneralComponentActions
from ..helpers.manager import WazuhManager
from ..helpers.indexer import WazuhIndexer
from ..helpers.dashboard import WazuhDashboard
from ..helpers.central import WazuhCentralComponents
from modules.testing.utils import logger
from ..helpers.utils import Utils


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


def test_parametros(wazuh_params):
    #logger.error(WazuhDashboard.get_dashboard_version(wazuh_params['dashboard']))
    #for indexer_params in wazuh_params['indexers']:
    #    logger.error(WazuhIndexer.get_indexer_version(indexer_params))

    #logger.error(WazuhDashboard.isDashboard_active(wazuh_params['dashboard']))


    #logger.error(WazuhDashboard.isDashboardKeystore_working(wazuh_params['dashboard']))
    #for indexer_params in wazuh_params['indexers']:
    #    logger.error(WazuhIndexer.areIndexer_internalUsers_complete(indexer_params))

    wazuh_api = WazuhAPI(wazuh_params['dashboard'], component='dashboard')
    logger.error(WazuhDashboard.areIndexes_working(wazuh_api))
    
""" def test_installation(wazuh_params):
    # Disabling firewall for all managers
    for manager_name, manager_params in wazuh_params['managers'].items():
        Utils.check_inventory_connection(manager_params)
        HostConfiguration.disable_firewall(manager_params)

    # Certs create and scp from master to worker
    HostConfiguration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'])

    # Install central components and perform checkfile testing
    for manager_name, manager_params in wazuh_params['managers'].items():
        WazuhCentralComponents.perform_install_and_scan_for_aio(manager_params, wazuh_params)

    # Validation of directory of the components
    for manager in wazuh_params['managers'].values():
        assert HostInformation.dir_exists(manager, WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is not present in {HostInformation.get_os_name_and_version_from_inventory(manager)}')


def test_component_status(wazuh_params):
    assert 'active' in GeneralComponentActions.get_component_status(wazuh_params['master'], 'wazuh-manager'), logger.error(f'The manager in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["master"])} is not active')
    assert 'active' in GeneralComponentActions.get_component_status(wazuh_params['dashboard'], 'wazuh-dashboard'), logger.error(f'The dashboard in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["dashboard"])} is not active')
    for indexer_params in wazuh_params['indexers']:
        assert 'active' in GeneralComponentActions.get_component_status(indexer_params, 'wazuh-indexer'), logger.error(f'The indexer in {HostInformation.get_os_name_and_version_from_inventory(indexer_params)} is not active')
    assert 'active' in GeneralComponentActions.get_component_status(wazuh_params['master'], 'filebeat'), logger.error(f'The filebeat in {HostInformation.get_os_name_and_version_from_inventory(wazuh_params["master"])} is not active')


def test_manager_version(wazuh_params):
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_version(manager)
        assert wazuh_params['wazuh_version'] in manager_status, logger.error(f"The version {HostInformation.get_os_name_and_version_from_inventory(manager)} is not {wazuh_params['wazuh_version']} by using commands")
        wazuh_api = WazuhAPI(wazuh_params['master'])
        assert wazuh_params['wazuh_version'] in WazuhManager.get_manager_version(wazuh_api), logger.error(f"The version {HostInformation.get_os_name_and_version_from_inventory(manager)} is not {wazuh_params['wazuh_version']} in the API")


def test_manager_revision(wazuh_params):
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_revision(manager)
        assert wazuh_params['wazuh_revision'] in manager_status, logger.error(f"The revision {HostInformation.get_os_name_and_version_from_inventory(manager)} is not {wazuh_params['wazuh_revision']} by using commands")
        wazuh_api = WazuhAPI(wazuh_params['master'])
        assert wazuh_params['wazuh_revision'] in str(WazuhManager.get_manager_revision(wazuh_api)), logger.error(f"The revision {HostInformation.get_os_name_and_version_from_inventory(manager)} is not {wazuh_params['wazuh_revision']} in the API")


def test_manager_installed_directory(wazuh_params):
    for manager in wazuh_params['managers'].values():
        assert HostInformation.dir_exists(manager, WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is not present in {HostInformation.get_os_name_and_version_from_inventory(manager)}')
 """