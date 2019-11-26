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
def test_wazuh_manager_is_installed(host, ManagerRoleDefaults,
                                    wazuh_service, wazuh_owner):
    manager = host.package("wazuh-manager")
    manager_version = ManagerRoleDefaults["wazuh_manager_version"]

    if (ManagerRoleDefaults["wazuh_manager_sources_installation"]["enabled"]):
        ossec_init = host.file("/etc/ossec-init.conf")
        assert ossec_init.exists
        host.process.get(user=wazuh_owner, comm=wazuh_service)
    else:
        full_manager_version = get_full_version(manager)
        assert manager.is_installed
        assert full_manager_version.startswith(manager_version)


def test_wazuh_manager_version(host, ManagerRoleDefaults):
    manager_version = ManagerRoleDefaults["wazuh_manager_version"]
    ossec_init = host.file("/etc/ossec-init.conf")
    assert ossec_init.exists
    assert (manager_version[:-2] in ossec_init.content_string)


def test_wazuh_api_is_installed(host, ManagerRoleDefaults):
    api = host.package("wazuh-api")
    if (ManagerRoleDefaults["wazuh_api_sources_installation"]["enabled"]):
        api_package_json = host.file(ManagerRoleDefaults
                                     ["wazuh_manager_sources_installation"]
                                     ["user_dir"] +
                                     "/api/package.json")
        assert api_package_json.exists
    else:
        assert api.is_installed


def test_wazuh_api_version(host, ManagerRoleDefaults):
    if (ManagerRoleDefaults["wazuh_api_sources_installation"]["enabled"]):
        api = host.package("wazuh-api")
        manager_version = ManagerRoleDefaults["wazuh_manager_version"]
        api_package_json = host.file(ManagerRoleDefaults
                                     ["wazuh_manager_sources_installation"]
                                     ["user_dir"] +
                                     "/api/package.json")
        # formatting "version": "x.xx.x"
        json_version_search = ("\"version\": " +
                               "\"" + manager_version[:-2] + "\"")
        assert (json_version_search in api_package_json.content_string)
    else:
        api = host.package("wazuh-api")
        full_api_version = get_full_version(api)
        assert full_api_version.startswith(manager_version)


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
