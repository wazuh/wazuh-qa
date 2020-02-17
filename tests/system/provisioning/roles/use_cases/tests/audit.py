import json
import auxiliary_functions

def test_audit_alerts(host,elasticsearch_ip,api_user,api_pass,api_protocol,port):
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