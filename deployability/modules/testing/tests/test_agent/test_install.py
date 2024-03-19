import pytest

from ..helpers.manager import WazuhManager
from ..helpers.agent import WazuhAgent
from ..helpers.generic import HostConfiguration, CheckFiles, HostInformation, GeneralComponentActions
from ..helpers.constants import WAZUH_ROOT


def install_agent_callback(wazuh_params, agent_name, agent_params):
    WazuhAgent.install_agent(agent_params, agent_name, wazuh_params['wazuh_version'], wazuh_params['wazuh_revision'], wazuh_params['live'])


def perform_action_and_scan_for_agent(agent_params, agent_name, wazuh_params):
    result = CheckFiles.perform_action_and_scan(agent_params, lambda: install_agent_callback(wazuh_params, agent_name, agent_params))
    categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
    actions = ['added', 'modified', 'removed']

    # Selecting filter
    os_name = HostInformation.get_os_name_from_inventory(agent_params)
    if 'debian' in os_name:
        filter_data= {'/boot': {'added': [], 'removed': [], 'modified': ['grubenv']}, '/usr/bin': {'added': ['unattended-upgrade', 'gapplication', 'add-apt-repository', 'gpg-wks-server', 'pkexec', 'gpgsplit', 'watchgnupg', 'pinentry-curses', 'gpg-zip', 'gsettings', 'gpg-agent', 'gresource', 'gdbus', 'gpg-connect-agent', 'gpgconf', 'gpgparsemail', 'lspgpot', 'pkaction', 'pkttyagent', 'pkmon', 'dirmngr', 'kbxutil', 'migrate-pubring-from-classic-gpg', 'gpgcompose', 'pkcheck', 'gpgsm', 'gio', 'pkcon', 'gpgtar', 'dirmngr-client', 'gpg', 'filebeat', 'gawk', 'curl', 'update-mime-database', 'dh_installxmlcatalogs', 'appstreamcli','lspgpot'], 'removed': [], 'modified': []}, '/root': {'added': ['trustdb.gpg'], 'removed': [], 'modified': []}, '/usr/sbin': {'added': ['update-catalog', 'applygnupgdefaults', 'addgnupghome', 'install-sgmlcatalog', 'update-xmlcatalog'], 'removed': [], 'modified': []}}
    else:
        filter_data = {'/boot': {'added': [], 'removed': [], 'modified': ['grubenv']}, '/usr/bin': {'added': ['filebeat'], 'removed': [], 'modified': []}, '/root': {'added': ['trustdb.gpg'], 'removed': [], 'modified': []}, '/usr/sbin': {'added': [], 'removed': [], 'modified': []}}

    # Use of filters
    for directory, changes in result.items():
        if directory in filter_data:
            for change, files in changes.items():
                if change in filter_data[directory]:
                    result[directory][change] = [file for file in files if file.split('/')[-1] not in filter_data[directory][change]]

    # Testing the results
    for category in categories:
        for action in actions:
            assert result[category][action] == []

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

def test_installation(wazuh_params):
    # Disabling firewall for all managers
    for manager_name, manager_params in wazuh_params['managers'].items():
        HostConfiguration.disable_firewall(manager_params)
    for agent_name, agent_params in wazuh_params['agents'].items():
        HostConfiguration.disable_firewall(agent_params)

    # Certs create and Manager installation
    HostConfiguration.certs_create(wazuh_params['wazuh_version'], wazuh_params['master'], wazuh_params['dashboard'], wazuh_params['indexers'], wazuh_params['workers'])
    WazuhManager.install_manager(wazuh_params['master'], 'wazuh-1', wazuh_params['wazuh_version'])

    # Agent installation
    for agent_names, agent_params in wazuh_params['agents'].items():
        perform_action_and_scan_for_agent(agent_params, agent_names, wazuh_params)

    # Testing installation directory
    for agent in wazuh_params['agents'].values():
        assert HostInformation.dir_exists(agent, WAZUH_ROOT)

def test_status(wazuh_params):
    for agent in wazuh_params['agents'].values():
        agent_status = GeneralComponentActions.get_component_status(agent, 'wazuh-agent')
        assert 'loaded' in agent_status

def test_version(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert wazuh_params['wazuh_version'] in GeneralComponentActions.get_component_version(agent_params)

def test_revision(wazuh_params):
    for agent_names, agent_params in wazuh_params['agents'].items():
        assert wazuh_params['wazuh_revision'] in GeneralComponentActions.get_component_revision(agent_params)