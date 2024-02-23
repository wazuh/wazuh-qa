import grp
import pwd
import pytest
import re
import json

from ..helpers import constants, utils
from ..helpers.installer import WazuhInstaller
from ..helpers.checkfiles import CheckFile
from ..helpers.hostinformation import HostInformation

@pytest.fixture
def wazuh_params(request, live, one_line):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')

    dependencies = json.loads(re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'"\1"', re.sub(r'(\w+):', r'"\1":', dependencies)))

    return {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': dependencies,
        'live': live,
        'one_line': one_line
    }

def test_installation(wazuh_params):
    if wazuh_params['live']:
        aws_s3 = 'packages'
        repository = wazuh_params['wazuh_version'][0] + '.x'
    else:
        aws_s3 = 'packages-dev'
        repository = 'pre-release'

    hostinfo= HostInformation()
    install_args = (
        hostinfo.get_os_type(),
        wazuh_params['wazuh_version'],
        wazuh_params['wazuh_revision'],
        aws_s3,
        repository,
        wazuh_params['dependencies'].get('manager'),
        wazuh_params['one_line'],
        hostinfo.get_linux_distribution(),
        hostinfo.get_architecture()
    )
    checkfile= CheckFile()
    wazuh_installer= WazuhInstaller(*install_args)
    result = checkfile.perform_action_and_scan(lambda: wazuh_installer.install_agent())

    assert all('wazuh' in path or 'ossec' in path for path in result['added'])
    assert not any('wazuh' in path or 'ossec' in path for path in result['removed'])


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
