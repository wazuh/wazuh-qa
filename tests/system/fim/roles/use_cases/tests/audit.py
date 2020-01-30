import json
import auxiliary_functions

def test_rules_configured(host):
    with host.sudo():
        audit_loaded_rules = host.run("auditctl -l").stdout
        assert ("-a exit,always -F euid=1001 -F arch=b32 -S execve -k audit-wazuh-c" in host.file(audit_loaded_rules).content_string)
        assert ("-a exit,always -F euid=1001 -F arch=b64 -S execve -k audit-wazuh-c" in host.file(audit_loaded_rules).content_string)

def test_audit_alerts(host,elasticsearch_ip,api_user,api_pass,api_protocol,port):
    query = {
        "query": {
            "match": {
                "data.audit.exe": {
                    "query": "/usr/bin/ping",
                }
            }
        }
    }
    response = auxiliary_functions.api_call_elasticsearch(host,query,elasticsearch_ip,api_protocol,api_user,api_pass,port)
    response_dict = json.loads(response.stdout)
    audit_ping_alert_found = False

    if (response_dict["hits"]["total"]["value"] > 0):
        for hit in response_dict["hits"]["hits"]:
            try:
                if ("ping" in hit["_source"]["data"]["audit"]["command"]):
                    audit_ping_alert_found = True
            except:
                pass # Ignoring hits that don't have searched fields
        assert audit_ping_alert_found
    else:
        assert False
 
    query_test_file = {
        "query": {
            "wildcard": {
                "syscheck.path": {
                    "value": "/home/*/test_syscheck_file*"
                }
            }
        }
    }

    response_test_file = auxiliary_functions.api_call_elasticsearch(host,query_test_file,elasticsearch_ip,api_protocol,api_user,api_pass,port)
    response_dict_test_file = json.loads(response_test_file.stdout)
    test_file_alert_found = False
    if (response_dict_test_file["hits"]["total"]["value"] > 0):
        for hit in response_dict_test_file["hits"]["hits"]:
            try:
                if ("test_syscheck_file" in hit["_source"]["syscheck"]["path"]):
                    test_file_alert_found = True
            except:
                pass # Ignoring hits that don't have searched fields
        assert test_file_alert_found
    else:
        assert False