import pytest
import json


from ..helpers.manager import WazuhManager
from ..helpers.generic import HostConfiguration
wazuh_manager = WazuhManager()
host_configuration = HostConfiguration()

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

    wazuh_manager.manager_restart(params['workers'][0])

@pytest.fixture(autouse=True)
def setup_test_environment(wazuh_params):
    wazuh_params['workers'] = [wazuh_params['dependencies']['manager']]
    wazuh_params['master'] = wazuh_params['inventory']
    wazuh_params['indexers'] = [wazuh_params['inventory']]
    wazuh_params['dashboard'] = wazuh_params['inventory']


def test_stop(wazuh_params):

    wazuh_manager.manager_stop(wazuh_params['workers'][0])

    assert 'active ' in wazuh_manager.get_manager_status(wazuh_params['master'])
    assert 'inactive ' in wazuh_manager.get_manager_status(wazuh_params['workers'][0])


