import functools
import os
import pytest
import testinfra

wazuh_version = ""

@pytest.mark.filterwarnings('ignore')
def test_load_variables(host,node):
    wazuh_version = node['default']['wazuh-manager']['version']
    
@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh agent instances')
def test_wazuh_manager_package(host):
    name = "wazuh-manager"
    version = wazuh_version
    pkg = host.package(name)
    assert pkg.is_installed
    assert pkg.version.startswith(version)

@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh agent instances')
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
        assert manager.is_running
    elif distribution == 'ubuntu':
        # assert manager.is_running
        assert manager.is_enabled
