import grp
import pwd
import pytest
import json
import re

from ..helpers.manager import WazuhManager
from ..helpers.generic import HostConfiguration, HostInformation
wazuh_manager = WazuhManager()
host_configuration = HostConfiguration()


def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')
    inventory = request.config.getoption('--inventory')

    return {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': dependencies,
        'inventory': inventory

    }

def test_installation(wazuh_params):
    
    managers = [wazuh_params['inventory'], wazuh_params['dependencies']['manager']]
    indexers = [wazuh_params['inventory']]

    host_configuration.sshd_config(wazuh_params['inventory'])
    host_configuration.sshd_config(wazuh_params['dependencies']['manager'])

    host_configuration.disable_firewall(wazuh_params['inventory'])
    host_configuration.disable_firewall(wazuh_params['dependencies']['manager'])

    host_configuration.certs_create(wazuh_params['inventory'], wazuh_params['inventory'], indexers, managers)

    host_configuration.scp_to(wazuh_params['inventory'], wazuh_params['dependencies']['manager'])

    #checkfile
    wazuh_manager.install_managers(managers)
    #checkfile
    assert 'active ' in wazuh_manager.get_manager_status(wazuh_params['inventory'])
    assert 'active ' in wazuh_manager.get_manager_status(wazuh_params['dependencies']['manager'])
    #validacion checkfile

def test_wazuh_user():
    pass


def test_wazuh_group():
    pass


def test_wazuh_configuration():
    pass

def test_wazuh_control():
    pass


def test_wazuh_service():
    pass


def test_wazuh_daemons():
    pass



"""
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