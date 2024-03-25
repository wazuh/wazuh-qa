import pytest

from ..helpers.agent import WazuhAgent
from ..helpers.constants import WAZUH_ROOT
from ..helpers.generic import HostInformation, GeneralComponentActions, Waits
from ..helpers.manager import WazuhManager, WazuhAPI
from ..helpers.logger.logger import logger


@pytest.fixture
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
    wazuh_params['agents'] = [value for key, value in targets_dict.items() if key.startswith('agent-')]
    wazuh_params['indexers'] = [value for key, value in targets_dict.items() if key.startswith('node-')]
    wazuh_params['dashboard'] = targets_dict.get('dashboard', wazuh_params['master'])

    # If there are no indexers, we choose wazuh-1 by default
    if not wazuh_params['indexers']:
        wazuh_params['indexers'].append(wazuh_params['master'])

    wazuh_params['managers'] = {key: value for key, value in targets_dict.items() if key.startswith('wazuh-')}
    wazuh_params['agents'] = {key: value for key, value in targets_dict.items() if key.startswith('agent-')}

def test_uninstall(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert GeneralComponentActions.isComponentActive(agent_params, 'wazuh-agent'), logger.error(f'{agent_names} is not Active before the installation')
        assert HostInformation.dir_exists(agent_params, WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is not present in the host {agent_names}')

    # Agent installation
    for agent_names, agent_params in wazuh_params['agents'].items():
        WazuhAgent.perform_uninstall_and_scan_for_agent(agent_params,wazuh_params)

    # Manager uninstallation status check
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert 'Disconnected' in WazuhManager.get_agent_control_info(wazuh_params['master']), logger.error(f'{agent_names} is still connected in the Manager')

def test_agent_uninstalled_directory(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert not HostInformation.dir_exists(agent_params, WAZUH_ROOT), logger.error(f'The {WAZUH_ROOT} is still present in the agent {agent_names}')

def test_isActive(wazuh_params):
    wazuh_api = WazuhAPI(wazuh_params['master'])
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert not GeneralComponentActions.isComponentActive(agent_params, 'wazuh-agent'), logger.error(f'{agent_names} is still active by command')

        expected_condition_func = lambda: 'disconnected' == WazuhAgent.get_agent_status(wazuh_api, agent_names)
        Waits.dynamic_wait(expected_condition_func, cycles=10, waiting_time=20)
