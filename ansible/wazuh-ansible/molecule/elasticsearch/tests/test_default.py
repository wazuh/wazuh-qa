import os
import sys

import testinfra.utils.ansible_runner
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../../_utils/'))
from test_utils import get_full_version


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("all")


@pytest.fixture(scope="module")
def ElasticRoleDefaults(host):
    return host.ansible(
        "include_vars",
        (
            "../../roles/elastic-stack/"
            "ansible-elasticsearch/defaults/main.yml"
        ),
    )["ansible_facts"]


def test_elasticsearch_is_installed(host, ElasticRoleDefaults):
    """Test if the elasticsearch package is installed."""
    elasticsearch = host.package("elasticsearch")
    es_version = ElasticRoleDefaults["elastic_stack_version"]
    es_full_version = get_full_version(elasticsearch)
    assert elasticsearch.is_installed
    assert es_full_version.startswith(es_version)


def test_elasticsearch_is_running(host):
    """Test if the services are enabled and running."""
    elasticsearch = host.service("elasticsearch")
    assert elasticsearch.is_enabled
    assert elasticsearch.is_running
