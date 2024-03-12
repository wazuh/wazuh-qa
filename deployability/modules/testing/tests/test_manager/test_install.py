import pytest
import json

from ..helpers.manager import WazuhManager
from ..helpers.generic import HostConfiguration, CheckFiles

wazuh_manager = WazuhManager()
host_configuration = HostConfiguration()
checkfiles = CheckFiles()

@pytest.fixture
def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')
    inventory = request.config.getoption('--inventory')

    return {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': json.loads(dependencies.replace("{", "{\"").replace(":", "\":\"").replace(",", "\",\"").replace("}", "\"}").replace(' ', '')),
        'inventory': inventory

    }

@pytest.fixture(autouse=True)
def setup_test_environment(wazuh_params):
    wazuh_params['workers'] = [wazuh_params['dependencies']['wazuh-2']]
    wazuh_params['master'] = wazuh_params['inventory']
    wazuh_params['indexers'] = [wazuh_params['inventory']]
    wazuh_params['dashboard'] = wazuh_params['inventory']

def test_installation(wazuh_params):
    managers = {
        'wazuh-1': wazuh_params['master'],
        'wazuh-2': wazuh_params['workers'][0]
    }

    # Disabling firewall for all managers
    for manager_name, manager_params in managers.items():
        host_configuration.disable_firewall(manager_params)

    # Certs create and scp from master to worker
    host_configuration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'])
    host_configuration.scp_to(wazuh_params['master'], wazuh_params['workers'][0], 'wazuh-install-files.tar')


    def install_manager_callback(wazuh_params, manager_name, manager_params):
        wazuh_manager.install_manager(manager_params, manager_name, wazuh_params['wazuh_version'])

    def perform_action_and_scan_for_manager(manager_params, manager_name):
        result = checkfiles.perform_action_and_scan(manager_params, lambda: install_manager_callback(wazuh_params, manager_name, manager_params))
        print(manager_name)
        print(result)
        categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
        actions = ['added', 'modified', 'removed']

        #for category in categories:
        #    for action in actions:
        #        assert result[category][action] == []

    # Combine the code using a loop over managers
    for manager_name, manager_params in managers.items():
        perform_action_and_scan_for_manager(manager_params, manager_name)

    # Configuring cluster for all managers
    hex16_code = 'eecda366dded9b32bcfbf3b057bf3ede'
    for manager_name, manager_params in managers.items():
        node_type = 'master' if manager_name == 'wazuh-1' else 'worker'
        wazuh_manager.configuring_clusters(manager_params, manager_name, node_type, 'master', hex16_code, 'no')

    # Cluster info check
    cluster_info = wazuh_manager.get_cluster_info(managers['wazuh-1'])

    assert 'wazuh-1' in cluster_info
    assert 'wazuh-2' in cluster_info