import functools
import os
import pytest
import testinfra

test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('manager' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def test_wazuh_agent_package(host,get_wazuh_version):
    name = "wazuh-agent"
    version = get_wazuh_version
    pkg = host.package(name)
    assert pkg.is_installed
    assert pkg.version.startswith(version)

@pytest.mark.skipif('manager' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def test_wazuh_agent_services_are_running(host):
    """
    Test if the services are enabled and running.
    """
    agent = host.service("wazuh-agent")
    with host.sudo():
        assert agent.is_running
        assert agent.is_enabled

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('manager' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
@pytest.mark.parametrize("wazuh_service, wazuh_owner", (
        ("ossec-agentd", "ossec"),
        ("ossec-execd", "root"),
        ("ossec-syscheckd", "root"),
        ("wazuh-modulesd", "root"),
))
def test_wazuh_agent_processes_running(host, wazuh_service, wazuh_owner):
    host.process.get(user=wazuh_owner, comm=wazuh_service)