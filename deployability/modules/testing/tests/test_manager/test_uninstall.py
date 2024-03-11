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

    params = {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': json.loads(dependencies.replace("{", "{\"").replace(":", "\":\"").replace(",", "\",\"").replace("}", "\"}").replace(' ', '')),
        'inventory': inventory

    }

    yield params

    wazuh_manager.uninstall_manager(params['master'])

@pytest.fixture(autouse=True)
def setup_test_environment(wazuh_params):
    wazuh_params['workers'] = [wazuh_params['dependencies']['manager']]
    wazuh_params['master'] = wazuh_params['inventory']
    wazuh_params['indexers'] = [wazuh_params['inventory']]
    wazuh_params['dashboard'] = wazuh_params['inventory']


def test_uninstall(wazuh_params):
    def uninstall_manager_callback(wazuh_params):
        wazuh_manager.uninstall_manager(wazuh_params['workers'][0])

    result = checkfiles.perform_action_and_scan(wazuh_params['workers'][0], lambda: uninstall_manager_callback(wazuh_params))

    #------------------------------------------------
    print("added: " + str(len(result['added'])))

    print("removed: " + str(len(result['removed'])))
    #------------------------------------------------

    assert all('wazuh' in path or 'ossec' in path or 'filebeat' in path for path in result['removed'])
    assert not any('wazuh' in path or 'ossec' in path or 'filebeat' in path for path in result['added'])
