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
    return {
        'wazuh_version': request.config.getoption('--wazuh_version'),
        'wazuh_revision': request.config.getoption('--wazuh_revision'),
    }

def test_uninstallation(wazuh_params):
    uninstall_args = (
        actions.get_os_type(),
        wazuh_params['wazuh_version'],
        wazuh_params['wazuh_revision'],
        actions.get_linux_distribution()
    )

    result = actions.perform_action_and_scan(lambda: actions.uninstall_wazuh_agent(*uninstall_args))

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


def test_config_is_not_maintained():
    assert not constants.WAZUH_CONF.exists(), "Wazuh config file waz found."
    assert not constants.LOCAL_INTERNAL_OPTIONS.exists(), "Local internal options file was found."