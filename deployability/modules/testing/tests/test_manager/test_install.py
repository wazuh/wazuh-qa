import pytest
import json

from ..helpers.manager import WazuhManager
from ..helpers.generic import HostConfiguration, CheckFiles, HostInformation

wazuh_manager = WazuhManager()
host_configuration = HostConfiguration()
checkfiles = CheckFiles()
host_information = HostInformation()

def install_manager_callback(wazuh_params, manager_name, manager_params):
    wazuh_manager.install_manager(manager_params, manager_name, wazuh_params['wazuh_version'])

def perform_action_and_scan_for_manager(manager_params, manager_name, wazuh_params):
    result = checkfiles.perform_action_and_scan(manager_params, lambda: install_manager_callback(wazuh_params, manager_name, manager_params))
    categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
    actions = ['added', 'modified', 'removed']

    # Selecting filter
    os_name = host_information.get_os_name_from_inventory(manager_params)
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

    # Install managers and perform checkfile testing
    for manager_name, manager_params in managers.items():
        perform_action_and_scan_for_manager(manager_params, manager_name, wazuh_params)

    # Configuring cluster for all managers
    hex16_code = 'eecda366dded9b32bcfbf3b057bf3ede'
    for manager_name, manager_params in managers.items():
        node_type = 'master' if manager_name == 'wazuh-1' else 'worker'
        wazuh_manager.configuring_clusters(manager_params, manager_name, node_type, 'master', hex16_code, 'no')

    # Cluster info check
    cluster_info = wazuh_manager.get_cluster_info(managers['wazuh-1'])

    assert 'wazuh-1' in cluster_info
    assert 'wazuh-2' in cluster_info