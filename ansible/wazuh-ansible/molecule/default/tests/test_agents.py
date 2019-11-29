import os
import sys

import testinfra.utils.ansible_runner
import pytest

sys.path.append(
                os.path.join(os.path.dirname(__file__), '../../_utils/')
                )  # noqa: E402
from test_utils import get_full_version, MOL_PLATFORM

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent-{}".format(MOL_PLATFORM))


@pytest.fixture(scope="module")
def AgentRoleDefaults(host):
    return host.ansible(
        "include_vars",
        (
            "../../roles/wazuh/"
            "ansible-wazuh-agent/defaults/main.yml"
        ),
    )["ansible_facts"]


def test_wazuh_agent_is_installed(host, AgentRoleDefaults):
    agent = host.package("wazuh-agent")
    if (AgentRoleDefaults["wazuh_agent_sources_installation"]["enabled"]):
        ossec_init = host.file("/etc/ossec-init.conf")
        assert ossec_init.exists
    else:
        assert agent.is_installed


def test_agent_version(host, AgentRoleDefaults):
    agent = host.package("wazuh-agent")
    agent_version = AgentRoleDefaults["wazuh_agent_version"]
    if (AgentRoleDefaults["wazuh_agent_sources_installation"]["enabled"]):
        ossec_init = host.file("/etc/ossec-init.conf")
        assert (agent_version[:-2] in ossec_init.content_string)
    else:
        full_agent_version = get_full_version(agent)
        assert full_agent_version.startswith(agent_version)


@pytest.mark.parametrize(
    "wazuh_service, wazuh_owner",
    (
        ("ossec-agentd", "ossec"),
        ("ossec-execd", "root"),
        ("ossec-syscheckd", "root"),
        ("wazuh-modulesd", "root"),
    ),
)
def test_wazuh_processes_running(host, wazuh_service, wazuh_owner):
    master = host.process.get(user=wazuh_owner, comm=wazuh_service)
    assert master.args == "/var/ossec/bin/" + wazuh_service
