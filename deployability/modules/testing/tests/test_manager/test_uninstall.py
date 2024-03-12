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

    return params


@pytest.fixture(autouse=True)
def setup_test_environment(wazuh_params):
    wazuh_params['workers'] = [wazuh_params['dependencies']['wazuh-2']]
    wazuh_params['master'] = wazuh_params['inventory']
    wazuh_params['indexers'] = [wazuh_params['inventory']]
    wazuh_params['dashboard'] = wazuh_params['inventory']


def test_uninstall(wazuh_params):
    managers = {
        'wazuh-1': wazuh_params['master'],
        'wazuh-2': wazuh_params['workers'][0]
    }
    def uninstall_manager_callback(manager_params):
        wazuh_manager.uninstall_manager(manager_params)

    def perform_action_and_scan_for_manager(manager_params):
        result = checkfiles.perform_action_and_scan(manager_params, lambda: uninstall_manager_callback(manager_params))

        categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
        actions = ['added', 'modified', 'removed']

        for category in categories:
            for action in actions:
                assert result[category][action] == []

    for manager_name, manager_params in managers.items():
        perform_action_and_scan_for_manager(manager_params)