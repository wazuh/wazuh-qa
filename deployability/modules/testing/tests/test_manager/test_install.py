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

    # sshd configuration for scp
    host_configuration.sshd_config(wazuh_params['master'])
    host_configuration.sshd_config(wazuh_params['workers'][0])

    # Disabling firewall
    host_configuration.disable_firewall(wazuh_params['master'])
    host_configuration.disable_firewall(wazuh_params['workers'][0])

    # Certs create and scp from master to worker
    host_configuration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'])
    host_configuration.scp_to(wazuh_params['master'], wazuh_params['workers'][0])

    # Install manager in master
    wazuh_manager.install_manager(wazuh_params['master'], 'wazuh-1', wazuh_params['wazuh_version'])

    # Install manager and checkfile
    def install_manager_callback(wazuh_params):
        wazuh_manager.install_manager(wazuh_params['workers'][0], 'wazuh-2', wazuh_params['wazuh_version'])

    result = checkfiles.perform_action_and_scan(wazuh_params['workers'][0], lambda: install_manager_callback(wazuh_params))

    assert all('wazuh' in path or 'ossec' in path or 'filebeat' in path for path in result['added'])
    assert not any('wazuh' in path or 'ossec' in path or 'filebeat' in path for path in result['removed'])

    # Configuring cluster
    wazuh_manager.configuring_clusters(wazuh_params['master'], 'wazuh-1', 'master', 'master','eecda366dded9b32bcfbf3b057bf3ede', 'no')
    wazuh_manager.configuring_clusters(wazuh_params['workers'][0], 'wazuh-2', 'worker', 'master','eecda366dded9b32bcfbf3b057bf3ede', 'no')
    
    # Cluster info check
    cluster_info = wazuh_manager.get_cluster_info(wazuh_params['master'])

    assert 'wazuh-1' in cluster_info
    assert 'wazuh-2' in cluster_info 
