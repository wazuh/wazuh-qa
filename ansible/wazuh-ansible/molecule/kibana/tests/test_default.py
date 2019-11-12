import os
import json

import testinfra.utils.ansible_runner
import pytest

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


@pytest.fixture(scope="module")
def KibanaRoleDefaults(host):
    return host.ansible(
        "include_vars",
        (
            "../../../wazuh-ansible/roles/elastic-stack/"
            "ansible-kibana/defaults/main.yml"
        ),
    )["ansible_facts"]


def test_port_kibana_is_open(host):
    """Test if the port 5601 is open and listening to connections."""
    host.socket("tcp://0.0.0.0:5601").is_listening


def test_find_correct_elasticsearch_version(host, KibanaRoleDefaults):
    """Test if we find the kibana/elasticsearch version in package.json"""
    elastic_stack_version = KibanaRoleDefaults["elastic_stack_version"]
    kibana = host.file("/usr/share/kibana/plugins/wazuh/package.json").content
    kibana_dict = json.loads(kibana)
    assert kibana_dict['kibana']['version'] == elastic_stack_version


def test_wazuh_plugin_installed(host):
    """Make sure there is a plugin wazuh directory."""
    kibana = host.file("/usr/share/kibana/plugins/wazuh/")

    assert kibana.is_directory
