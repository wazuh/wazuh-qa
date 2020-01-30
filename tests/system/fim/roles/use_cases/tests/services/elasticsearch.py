import json
import auxiliary_functions

es_log_path = "/mnt/ephemeral/elasticsearch/log/wazuh.log"

def test_elasticsearch_is_installed_version(host,elastic_version):
#     """Test if the elasticsearch package is installed."""
    with host.sudo():
        elasticsearch = host.package("elasticsearch")
        assert host.package("elasticsearch").is_installed
        assert elasticsearch.version.startswith(elastic_version)

def test_elasticsearch_is_running_enabled(host):
    """Test if the services are enabled and running."""
    with host.sudo():
        elasticsearch = host.service("elasticsearch")
        assert elasticsearch.is_enabled
        assert elasticsearch.is_running

# def test_elasticsearch_no_error_logs(host):       # Disabled until configuring log file in elasticsearch.yml
#     """Test if elasticsearch log shows no error"""
#     with host.sudo():
#         assert not ("ERROR" in host.file(es_log_path).content_string)

def test_elasticsearch_curl(host,elasticsearch_ip,api_user,api_pass,api_protocol,elastic_version, port):
    """Test if elasticsearch curl response is ok"""
    query = "" # Empty query to call main API endpoint
    response = auxiliary_functions.api_call_elasticsearch(host,query,elasticsearch_ip,api_protocol,api_user,api_pass,port)

    response_dict = json.loads(response.stdout)
    
    assert (response.rc == 0)
    assert (elastic_version in response_dict["version"]["number"])
    assert ("wazuh" in response_dict.get("cluster_name"))

