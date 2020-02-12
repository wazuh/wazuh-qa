import json
import auxiliary_functions

HOSTS_WITH_FIM_ENABLED = 2 # Fim will be enabled and triggered on RHEL and Windows Agent
FIM_FILE_TEST = "test_file_for_fim"

def test_fim_alerts(host,elasticsearch_ip,api_user,api_pass,api_protocol,port):
    query = {
        "query": {
            "wildcard": {
                "syscheck.path": {
                    "value": "*" + FIM_FILE_TEST + "*" # Test file to trigger the fim alerts
                }
            }
        }
    }

    response = auxiliary_functions.api_call_elasticsearch(host,query,elasticsearch_ip,api_protocol,api_user,api_pass,port)
    response_dict = json.loads(response.stdout)
    fim_count = 0

    if (response_dict["hits"]["total"]["value"] > 0):
        for hit in response_dict["hits"]["hits"]:
            try:
                print (hit["_source"]["syscheck"]["path"])
                if (FIM_FILE_TEST in hit["_source"]["syscheck"]["path"]):
                    fim_count+=1
            except:
                pass # Ignoring hits that don't have searched fields
        assert (fim_count >= HOSTS_WITH_FIM_ENABLED)
    else:
        assert False