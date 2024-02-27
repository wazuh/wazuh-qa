import grp
import pwd
import pytest

from ..helpers import constants, utils
from ..helpers.installer import WazuhManagerInstaller
from ..helpers.checkfiles import CheckFile
from ..helpers.hostinformation import HostInformation

@pytest.fixture
def wazuh_params(request):
    return {
        'wazuh_version': request.config.getoption('--wazuh_version'),
        'live': request.config.getoption('--live')
    }

def test_installation(wazuh_params):
    aws_s3 = 'packages' if wazuh_params['live'] else 'packages-dev'

    install_args = (
        wazuh_params['wazuh_version'][0:3],
        aws_s3
    )
    checkfile= CheckFile()
    wazuh_installer= WazuhManagerInstaller(*install_args)
    result = checkfile.perform_action_and_scan(lambda: wazuh_installer.install_manager())


    print(result)
    assert all('wazuh' in path or 'ossec' in path for path in result['added'])
    assert not any('wazuh' in path or 'ossec' in path for path in result['removed'])
"""

def test_wazuh_user():
    all_users = [x[0] for x in pwd.getpwall()]
    assert constants.WAZUH_USER in all_users, "Wazuh user not found."


def test_wazuh_group():
    all_groups = [x[0] for x in grp.getgrall()]
    assert constants.WAZUH_GROUP in all_groups, "Wazuh group not found."


def test_wazuh_configuration():
    assert constants.CONFIGURATIONS_DIR.exists(), "Configuration directory not found."
    assert constants.WAZUH_CONF.exists(), "Configuration file not found."


def test_wazuh_control():
    assert constants.BINARIES_DIR.exists(), "Binaries directory not found."
    assert constants.WAZUH_CONTROL.exists(), "Wazuh control binary not found."


def test_wazuh_service(component):
    expected_service = component
    assert utils.get_service() == expected_service, f"Installed service is not the expected."


def test_wazuh_daemons():
    actual_daemons = utils.get_daemons_status()
    expected_daemons = constants.AGENT_DAEMONS

    for daemon in expected_daemons:
        assert daemon in actual_daemons.keys(), f"{daemon} not found."
"""