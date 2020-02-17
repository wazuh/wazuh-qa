import os
import testinfra
import sys
import testinfra.utils.ansible_runner
import pytest

def test_wazuh_manager_is_installed(host, wazuh_version, installation_type):
    ossec_init = host.file("/etc/ossec-init.conf")
    assert ossec_init.exists

@pytest.mark.parametrize(
    "wazuh_service, wazuh_owner",
    (
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
    
def test_wazuh_worker_is_running(host, wazuh_service, wazuh_owner):
    host.process.get(user=wazuh_owner, comm=wazuh_service)

def test_wazuh_api_is_installed(host, installation_type):
    api = host.package("wazuh-api")
    if (installation_type == "sources"):
        api_package_json = host.file("/var/ossec/api/package.json")
        assert api_package_json.exists
    else:
        assert api.is_installed

def test_wazuh_api_version(host, wazuh_version, installation_type, installation_path):
    api = host.package("wazuh-api")
    if (installation_type == "sources"):
        api_package_json = host.file(installation_path + "/api/package.json")
        # formatting "version": "x.xx.x"
        json_version_search = ("\"version\": " +
                               "\"" + wazuh_version[:-2] + "\"")
        assert (json_version_search in api_package_json.content_string)
    else:
        assert api.version.startswith(wazuh_version[:-2])


@pytest.mark.parametrize(
    "wazuh_file, wazuh_owner, wazuh_group, wazuh_mode",
    [
        ("/var/ossec/etc/sslmanager.cert", "root", "root", 0o640),
        ("/var/ossec/etc/sslmanager.key", "root", "root", 0o640),
        ("/var/ossec/etc/rules/local_rules.xml", "ossec", "ossec", 0o660),
        ("/var/ossec/etc/lists/audit-keys", "ossec", "ossec", 0o660),
    ],
)

def test_wazuh_files(host, wazuh_file, wazuh_owner, wazuh_group, wazuh_mode):
    """Test if Wazuh related files exist and have proper owners and mode."""
    wazuh_file_host = host.file(wazuh_file)
    assert wazuh_file_host.user == wazuh_owner
    assert wazuh_file_host.group == wazuh_group
    assert wazuh_file_host.mode == wazuh_mode

def test_open_ports_worker(host):
    # Using shell due to hosts.socket not being able to regex filter
    assert (host.run("netstat -tulnap | grep 1514 | grep LISTEN").rc == 0)
    assert (host.run("netstat -tulnap | grep 1516 | grep ESTABLISHED").rc == 0)       

def test_filebeat_is_installed(host):
    assert host.package("filebeat").is_installed

def test_filebeat_version(host, elastic_version):
    assert host.package("filebeat").version.startswith(elastic_version)