import requests


STATE_INDEX_NAME = 'wazuh-vulnerabilities-states'

# Indexer API methods
def get_indexer_values(host_manager, credentials={'user': 'admin', 'password': 'changeme'}, index='wazuh-alerts*'):
    url = f"https://{host_manager.get_master_ip()}:9200/{index}_search?"
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url=url, params={'pretty': 'true'}, json=query, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']))
    return response.text
