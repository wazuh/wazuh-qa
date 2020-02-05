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
    """
    Test if the services are enabled and running.
    """
    manager = host.service("wazuh-manager")
    with host.sudo():
        assert manager.is_running
        assert manager.is_enabled

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh agent instances')
@pytest.mark.parametrize(
    "wazuh_service, wazuh_owner",
    (
        ("ossec-authd", "root"),
        ("ossec-execd", "root"),
        ("ossec-analysisd", "ossec"),
        ("ossec-syscheckd", "root"),
        ("ossec-remoted", "ossecr"),
        # Testinfra detects "ossec-logcollector" as "ossec-logcollec"
        ("ossec-logcollec", "root"),
        ("ossec-monitord", "ossec"),
        ("wazuh-db", "ossec"),
        ("wazuh-modulesd", "root"),
    ),
)
def test_wazuh_manager_processes_running(host, wazuh_service, wazuh_owner):        
    host.process.get(user=wazuh_owner, comm=wazuh_service)
