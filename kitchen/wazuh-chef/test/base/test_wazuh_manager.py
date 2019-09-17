import functools
import os
import pytest
import testinfra

test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def test_wazuh_manager_package(host):
    name = "wazuh-manager"
    version = "3.10"
    pkg = host.package(name)
    assert pkg.is_installed
    assert pkg.version.startswith(version)

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def get_wazuh_version():
    """This return the version of Wazuh."""
    return "3.10"

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def test_wazuh_packages_are_installed(host):
    """Test if the main packages are installed."""
    manager = host.package("wazuh-manager")
    #api = host.package("wazuh-api")

    distribution = host.system_info.distribution.lower()
    if distribution == 'centos':
        if host.system_info.release == "7":
            assert manager.is_installed
            assert manager.version.startswith(get_wazuh_version())
            #assert api.is_installed
            #assert api.version.startswith(get_wazuh_version())
        elif host.system_info.release.startswith("6"):
            assert manager.is_installed
            assert manager.version.startswith(get_wazuh_version())
    elif distribution == 'ubuntu':
        assert manager.is_installed
        assert manager.version.startswith(get_wazuh_version())


@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def test_wazuh_services_are_running(host):
    """Test if the services are enabled and running.
    When assert commands are commented, this means that the service command has
    a wrong exit code: https://github.com/wazuh/wazuh-ansible/issues/107
    """
    manager = host.service("wazuh-manager")

    distribution = host.system_info.distribution.lower()
    if distribution == 'centos':
        # assert manager.is_running
        assert manager.is_enabled
    elif distribution == 'ubuntu':
        # assert manager.is_running
        assert manager.is_enabled
