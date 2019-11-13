import os
import sys

import testinfra.utils.ansible_runner
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../../_utils/'))
from test_utils import get_full_version, MOL_PLATFORM

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("manager-{}".format(MOL_PLATFORM))


@pytest.fixture(scope="module")
def ManagerRoleDefaults(host):
    return host.ansible(
        "include_vars",
        (
            "../../roles/wazuh/"
            "ansible-wazuh-manager/defaults/main.yml"
        ),
    )["ansible_facts"]


@pytest.fixture(scope="module")
def FilebeatRoleDefaults(host):
    return host.ansible(
        "include_vars",
        (
            "../../roles/wazuh/"
            "ansible-filebeat/defaults/main.yml"
        ),
    )["ansible_facts"]


def test_agents_registered_on_manager(host):
    cmd = host.run("/var/ossec/bin/manage_agents -l")
    assert "agent-{}".format(MOL_PLATFORM) in cmd.stdout


def test_wazuh_packages_are_installed(host, ManagerRoleDefaults):
    """Test if the main packages are installed."""
    manager = host.package("wazuh-manager")
    api = host.package("wazuh-api")

    manager_version = ManagerRoleDefaults["wazuh_manager_version"]
    full_manager_version = get_full_version(manager)
    full_api_version = get_full_version(api)

    assert manager.is_installed
    assert full_manager_version.startswith(manager_version)
    assert api.is_installed
    assert full_api_version.startswith(manager_version)


def test_wazuh_services_are_running(host):
    """Test if the services are enabled and running.

    When assert commands are commented, this means that the service command has
    a wrong exit code: https://github.com/wazuh/wazuh-ansible/issues/107
    """
    manager = host.service("wazuh-manager")
    api = host.service("wazuh-api")

    distribution = host.system_info.distribution.lower()
    if distribution == "centos":
        # assert manager.is_running
        assert manager.is_enabled
        # assert not api.is_running
        assert api.is_enabled
    elif distribution == "ubuntu":
        # assert manager.is_running
        assert manager.is_enabled
        # assert api.is_running
        assert api.is_enabled


@pytest.mark.parametrize(
    "wazuh_file, wazuh_owner, wazuh_group, wazuh_mode",
    [
        ("/var/ossec/etc/sslmanager.cert", "root", "root", 0o640),
        ("/var/ossec/etc/sslmanager.key", "root", "root", 0o640),
        ("/var/ossec/etc/rules/local_rules.xml", "root", "ossec", 0o640),
        ("/var/ossec/etc/lists/audit-keys", "root", "ossec", 0o640),
    ],
)
def test_wazuh_files(host, wazuh_file, wazuh_owner, wazuh_group, wazuh_mode):
    """Test if Wazuh related files exist and have proper owners and mode."""
    wazuh_file_host = host.file(wazuh_file)

    assert wazuh_file_host.user == wazuh_owner
    assert wazuh_file_host.group == wazuh_group
    assert wazuh_file_host.mode == wazuh_mode


def test_open_ports(host):
    """Test if the main port is open and the agent-auth is not open."""
    distribution = host.system_info.distribution.lower()
    if distribution == "ubuntu":
        assert host.socket("tcp://0.0.0.0:1516").is_listening
        assert host.socket("tcp://0.0.0.0:1515").is_listening
        assert host.socket("tcp://0.0.0.0:1514").is_listening
    elif distribution == "centos":
        assert host.socket("tcp://0.0.0.0:1516").is_listening
        assert host.socket("tcp://127.0.0.1:1515").is_listening
        assert host.socket("tcp://127.0.0.1:1514").is_listening


def test_filebeat_is_installed(host, FilebeatRoleDefaults):
    """Test if the elasticsearch package is installed."""
    filebeat = host.package("filebeat")
    filebeat_version = FilebeatRoleDefaults["filebeat_version"]
    full_filebeat_version = get_full_version(filebeat)
    assert filebeat.is_installed
    assert full_filebeat_version.startswith(filebeat_version)
