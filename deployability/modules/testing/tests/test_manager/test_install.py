import pytest

from ..helpers.constants import WAZUH_ROOT
from ..helpers.executor import WazuhAPI
from ..helpers.generic import HostConfiguration, CheckFiles, HostInformation, GeneralComponentActions
from ..helpers.manager import WazuhManager


@pytest.fixture
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
    wazuh_params['indexers'] = [value for key, value in targets_dict.items() if key.startswith('node-')]
    wazuh_params['dashboard'] = targets_dict.get('dashboard', wazuh_params['master'])

    # If there are no indexers, we choose wazuh-1 by default
    if not wazuh_params['indexers']:
        wazuh_params['indexers'].append(wazuh_params['master'])

    wazuh_params['managers'] = {key: value for key, value in targets_dict.items() if key.startswith('wazuh-')}


def test_installation(wazuh_params):
    # Disabling firewall for all managers
    for manager_name, manager_params in wazuh_params['managers'].items():
        HostConfiguration.disable_firewall(manager_params)

    # Certs create and scp from master to worker
    HostConfiguration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'])

    for workers in wazuh_params['workers']:
        HostConfiguration.scp_to(wazuh_params['master'], workers, 'wazuh-install-files.tar')

    # Install managers and perform checkfile testing
    for manager_name, manager_params in wazuh_params['managers'].items():
        WazuhManager.perform_install_and_scan_for_manager(manager_params, manager_name, wazuh_params)

    # Configuring cluster for all managers
    hex16_code = 'eecda366dded9b32bcfbf3b057bf3ede'
    for manager_name, manager_params in wazuh_params['managers'].items():
        node_type = 'master' if manager_name == 'wazuh-1' else 'worker'
        WazuhManager.configuring_clusters(manager_params, manager_name, node_type, 'master', hex16_code, 'no')

    # Cluster info check
    cluster_info = WazuhManager.get_cluster_info(wazuh_params['master'])
    for manager_name, manager_params in wazuh_params['managers'].items():
        assert manager_name in cluster_info


def test_manager_status(wazuh_params):
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_status(manager, 'wazuh-manager')
        assert 'active' in manager_status


def test_manager_version(wazuh_params):
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_version(manager)
        assert wazuh_params['wazuh_version'] in manager_status
        wazuh_api = WazuhAPI(manager)
        assert wazuh_params['wazuh_version'] in WazuhManager.get_manager_version(wazuh_api)


def test_manager_revision(wazuh_params):
    for manager in wazuh_params['managers'].values():
        manager_status = GeneralComponentActions.get_component_revision(manager)
        assert wazuh_params['wazuh_revision'] in manager_status
        wazuh_api = WazuhAPI(manager)
        assert wazuh_params['wazuh_revision'] in str(WazuhManager.get_manager_revision(wazuh_api))


def test_manager_installed_directory(wazuh_params):
    for manager in wazuh_params['managers'].values():
        assert HostInformation.dir_exists(manager, WAZUH_ROOT)
