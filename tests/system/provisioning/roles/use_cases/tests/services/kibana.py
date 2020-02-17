import os
import testinfra
import requests
import sys

KIBANA_LOG_PATH = "/usr/share/kibana/optimize/wazuh-logs/wazuhapp.log"

def test_kibana_is_installed(host,elastic_version):
    """Test if the kibana package is installed."""
    with host.sudo():
        kibana = host.package("kibana")
        assert host.package("kibana").is_installed
        assert kibana.version.startswith(elastic_version)

def test_kibana_is_running(host):
    """Test if the services are enabled and running."""
    with host.sudo():
        kibana = host.service("kibana")
        assert kibana.is_enabled
        assert kibana.is_running

def test_kibana_log_errors(host):
    """Test if kibana log shows no error"""
    with host.sudo():
        assert not ("ERROR" in host.file(KIBANA_LOG_PATH).content_string)
        assert ("App ready to be used." in host.file(KIBANA_LOG_PATH).content_string)
