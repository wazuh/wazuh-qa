import os
import json

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_elasticsearch_is_installed(host):
    """Test if the elasticsearch package is installed."""
    elasticsearch = host.package("elasticsearch")
    assert elasticsearch.is_installed
    assert elasticsearch.version.startswith('7.3.2')


def test_elasticsearch_is_running(host):
    """Test if the services are enabled and running."""
    elasticsearch = host.service("elasticsearch")
    assert elasticsearch.is_enabled
    assert elasticsearch.is_running


def test_elasticsearch_has_xpack_config(host):
    """Test if xpack is enabled in elasticsearch config."""
    config = host.file("/etc/elasticsearch/elasticsearch.yml")
    assert config.contains("xpack.security.enabled: true")
    assert config.contains("xpack.security.transport.ssl.enabled: true")
    assert config.contains("xpack.security.http.ssl.enabled: true")


def test_elasticsearch_has_ssl(host):
    """Test if elasticsearch has SSL enabled."""
    cmd = host.run("curl -u elastic:elastic_pass -k https://127.0.0.1:9200")
    assert cmd.rc == 0
    result = json.loads(cmd.stdout)
    assert result["version"]["number"] == "7.3.2"
