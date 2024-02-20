import grp
import pwd
import pytest
from ..helpers import actions

from ..helpers import constants, utils


# @pytest.fixture(scope='module', autouse=True)
# def uninstall_wazuh():
#     service = utils.get_service()
#     daemon_name = 'wazuh-agent' if service == 'agent' else 'wazuh-manager'
#     utils.run_command('apt-get', ['purge', daemon_name, '-y'])

@pytest.fixture
def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    return {'wazuh_version': wazuh_version, 'wazuh_revision': wazuh_revision}

def test_installation(wazuh_params):
    result = actions.perform_action_and_scan(lambda: actions.install_wazuh_agent(actions.get_os_type(), wazuh_params['wazuh_version'] , wazuh_params['wazuh_revision'], 'packages', '4.x', '127.0.0.1', actions.get_linux_distribution(), actions.get_achitecture()))
    assert all('wazuh' in path or 'ossec' in path for path in result['added'])
    assert not any('wazuh' in path or 'ossec' in path for path in result['removed'])

def test_uninstallation(wazuh_params):
    result = actions.perform_action_and_scan(lambda: actions.uninstall_wazuh_agent(actions.get_os_type(), wazuh_params['wazuh_version'], wazuh_params['wazuh_revision'], actions.get_linux_distribution()))
    print(all('wazuh' in path or 'ossec' in path for path in result['removed']))
    print(not any('wazuh' in path or 'ossec' in path for path in result['added']))
    assert all('wazuh' in path or 'ossec' in path for path in result['removed'])
    assert not any('wazuh' in path or 'ossec' in path for path in result['added'])

def test_wazuh_user():
    all_users = [x[0] for x in pwd.getpwall()]
    assert constants.WAZUH_USER not in all_users, "Wazuh user found."


def test_wazuh_group():
    all_groups = [x[0] for x in grp.getgrall()]
    assert constants.WAZUH_GROUP not in all_groups, "Wazuh group found."


def test_process_not_running():
    assert not utils.is_process_alive('wazuh'), 'Wazuh process is running.'

""" 
def test_service_stopped():
    assert utils.get_service_status() == "inactive", "Service is active."


def test_ports_not_listening():
    assert not utils.is_port_listening(1514), 'Port 1514 is listening.'
    assert not utils.is_port_listening(1515), 'Port 1515 is listening.'


def test_config_is_maintained():
    assert constants.WAZUH_CONF.exists(), "Wazuh config file not found."
    assert constants.LOCAL_INTERNAL_OPTIONS.exists(), "Local internal options file not found." """