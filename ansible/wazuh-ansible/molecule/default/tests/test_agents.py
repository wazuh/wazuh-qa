import os
import pytest

import testinfra.utils.ansible_runner

MOL_PLATFORM = os.getenv('MOL_PLATFORM', 'centos7')

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('agent-{}'
                                                     .format(MOL_PLATFORM))


def get_wazuh_version():
    """This return the version of Wazuh."""
    return "3.10.2"


def test_wazuh_agent_is_installed(host):
    """Test if the main packages are installed."""
    agent = host.package("wazuh-agent")
    assert agent.is_installed


@pytest.mark.parametrize("wazuh_service, wazuh_owner", (
    ("ossec-agentd", "ossec"),
    ("ossec-execd", "root"),
    ("ossec-syscheckd", "root"),
    ("wazuh-modulesd", "root"),
))
def test_wazuh_processes_running(host, wazuh_service, wazuh_owner):
    master = host.process.get(user=wazuh_owner, comm=wazuh_service)
    assert master.args == "/var/ossec/bin/" + wazuh_service
