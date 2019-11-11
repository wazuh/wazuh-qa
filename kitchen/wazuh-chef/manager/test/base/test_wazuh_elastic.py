import functools
import os
import pytest
import testinfra

test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))

@pytest.mark.filterwarnings('ignore')
def test_elasticsearch_is_installed(host):
    """Test if the elasticsearch package is installed."""
    elasticsearch = host.package("elasticsearch")
    assert elasticsearch.is_installed
    assert elasticsearch.version.startswith('7.3.2')

@pytest.mark.filterwarnings('ignore')
def test_elasticsearch_is_running(host):
    """Test if the services are enabled and running."""
    elasticsearch = host.service("elasticsearch")
    assert elasticsearch.is_enabled
    assert elasticsearch.is_running