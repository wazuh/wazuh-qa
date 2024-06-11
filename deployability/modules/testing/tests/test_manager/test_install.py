# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from modules.testing.utils import logger
from ..helpers.constants import WAZUH_ROOT
from ..helpers.executor import WazuhAPI
from ..helpers.generic import HostConfiguration, HostInformation, GeneralComponentActions
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
    wazuh_params['indexers'] = [value for key, value in targets_dict.items() if key.startswith('node-')]
    wazuh_params['dashboard'] = targets_dict.get('dashboard', wazuh_params['master'])

    # If there are no indexers, we choose wazuh-1 by default
    if not wazuh_params['indexers']:
        wazuh_params['indexers'].append(wazuh_params['master'])

    wazuh_params['managers'] = {key: value for key, value in targets_dict.items() if key.startswith('wazuh-')}

def test_installation(wazuh_params):
    # Disabling firewall for all managers
    for manager_name, manager_params in wazuh_params['managers'].items():
        Utils.check_inventory_connection(manager_params)
        HostConfiguration.disable_firewall(manager_params)

    # Certs create and scp from master to worker
    HostConfiguration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'], wazuh_params['live'])

    for workers in wazuh_params['workers']:
        HostConfiguration.scp_to(wazuh_params['master'], workers, 'wazuh-install-files.tar')

    # Install managers and perform checkfile testing
    for manager_name, manager_params in wazuh_params['managers'].items():
        WazuhManager.install_manager(manager_params, manager_name, wazuh_params['wazuh_version'], wazuh_params['live'])

    # Validation of activity and directory of the managers
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_status(manager, 'wazuh-manager')
        assert 'active' in manager_status, logger.error(f'The {HostInformation.get_os_name_and_version_from_inventory(manager)} is not active')
        assert HostInformation.dir_exists(manager, WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is not present in {HostInformation.get_os_name_and_version_from_inventory(manager)}')

    # Configuring cluster for all managers
    hex16_code = 'eecda366dded9b32bcfbf3b057bf3ede'
    for manager_name, manager_params in wazuh_params['managers'].items():
        node_type = 'master' if manager_name == 'wazuh-1' else 'worker'
        WazuhManager.configuring_clusters(manager_params, manager_name, node_type, wazuh_params['master'], hex16_code, 'no')

    # Cluster info check
    cluster_info = WazuhManager.get_cluster_info(wazuh_params['master'])
    for manager_name, manager_params in wazuh_params['managers'].items():
        rest_of_managers = [k for k in wazuh_params['managers'].keys() if k != manager_name]
        assert manager_name in cluster_info, logger.error(f'The cluster {manager_name} is not connected to {rest_of_managers}')


def test_manager_status(wazuh_params):
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_status(manager, 'wazuh-manager')
        assert 'active' in manager_status, logger.error(f'The {HostInformation.get_os_name_and_version_from_inventory(manager)} is not active')


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
