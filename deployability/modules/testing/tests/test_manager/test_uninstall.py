# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from modules.testing.utils import logger
from ..helpers.constants import WAZUH_ROOT
from ..helpers.generic import HostInformation, GeneralComponentActions
from ..helpers.manager import WazuhManager



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
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_status(manager, 'wazuh-manager')
        assert 'active' in manager_status, logger.error(f'The {HostInformation.get_os_name_and_version_from_inventory(manager)} is not active')
    for _, manager_params in wazuh_params['managers'].items():
        WazuhManager.uninstall_manager(manager_params)

def test_manager_uninstalled_directory(wazuh_params):
    for manager in wazuh_params['managers'].values():
        assert not HostInformation.dir_exists(manager, WAZUH_ROOT), logger.error(f'In {HostInformation.get_os_name_and_version_from_inventory(manager)} {WAZUH_ROOT} is still present')
