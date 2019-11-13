import functools
import os
import pytest
import testinfra
import json


elk_version = ""

@pytest.mark.filterwarnings('ignore')
def test_load_variables(host,node):
      elk_version = node['default']['wazuh-elastic']['elastic_stack_version']

@pytest.mark.filterwarnings('ignore')
def test_elasticsearch_is_installed(host,node):
    """Test if the elasticsearch package is installed."""
    elasticsearch = host.package("elasticsearch")
    assert elasticsearch.is_installed
    assert elasticsearch.version.startswith(elk_version)

@pytest.mark.filterwarnings('ignore')
def test_elasticsearch_is_running(host):
    """Test if the services are enabled and running."""
    elasticsearch = host.service("elasticsearch")
    assert elasticsearch.is_enabled

    distribution = host.system_info.distribution.lower()
    if distribution == 'centos':
        assert elasticsearch.is_running

def test_port_kibana_is_open(host):
    """Test if the port 5601 is open and listening to connections."""
    host.socket("tcp://0.0.0.0:5601").is_listening

def test_port_nginx_is_open(host):
    """Test if the port 443 is open and listening to connections."""
    host.socket("tcp://0.0.0.0:443").is_listening

def test_find_correct_elasticsearch_version(host,node):
    """Test if we find the kibana/elasticsearch version in package.json"""
    kibana = host.file("/usr/share/kibana/plugins/wazuh/package.json")
    assert kibana.contains(elk_version)


def test_wazuh_plugin_installed(host):
    """Make sure there is a plugin wazuh directory."""
    kibana = host.file("/usr/share/kibana/plugins/wazuh/")
    assert kibana.is_directory