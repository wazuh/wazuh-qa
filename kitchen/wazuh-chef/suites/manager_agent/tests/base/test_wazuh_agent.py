import functools
import os
import pytest
import testinfra


wazuh_version = ""

@pytest.mark.filterwarnings('ignore')
def test_load_variables(host,node):
    wazuh_version = node['default']['wazuh-agent']['version']

@pytest.mark.filterwarnings('ignore')
@pytest.mark.skipif('manager' in os.environ.get('KITCHEN_INSTANCE'), reason='Skip on wazuh manager instances')
def test_wazuh_agent_package(host):
    name = "wazuh-agent"
    version = wazuh_version
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
