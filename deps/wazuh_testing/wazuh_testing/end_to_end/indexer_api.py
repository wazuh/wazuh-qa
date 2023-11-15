import requests


STATE_INDEX_NAME = 'wazuh-vulnerabilities-states'

# Indexer API methods
def get_vuln_state_value(host_manager, credentials={'user': 'wazuh', 'password': 'wazuh'}):
    url = f"https://{host_manager.get_master_ip(host_manager)}:9200/{STATE_INDEX_NAME}_search?"
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url=url, params={'pretty': 'true'}, json=query, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']))
    return response.text
