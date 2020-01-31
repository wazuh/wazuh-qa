import functools
import os
import pytest
import testinfra

test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh agent instances')
def test_wazuh_agent_package(host,get_wazuh_version):
    name = "wazuh-manager"
    version = get_wazuh_version
    pkg = host.package(name)
    assert pkg.is_installed
    assert pkg.version.startswith(version)

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('agent' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh agent instances')
def test_wazuh_packages_are_installed(host,get_wazuh_version):
    """Test if the main packages are installed."""
    manager = host.package("wazuh-manager")

    distribution = host.system_info.distribution.lower()
    if distribution == 'centos':
        if host.system_info.release.startswith("7"):
            assert manager.is_installed
            assert manager.version.startswith(get_wazuh_version)
        elif host.system_info.release.startswith("6"):
            assert manager.is_installed
            assert manager.version.startswith(get_wazuh_version)
    elif distribution == 'ubuntu':
        assert manager.is_installed
        assert manager.version.startswith(get_wazuh_version)


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