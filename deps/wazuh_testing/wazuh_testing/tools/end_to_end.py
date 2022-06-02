import requests


def get_alert_dashboard_api(ip_address='wazuh-manager', index='wazuh-alerts-4.x-*', query=None, credentials=None):

    url = f'https://{ip_address}:9200/{index}/_search?'

    response = requests.get(url=url, params={'pretty': 'true'}, json=query, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']))

    return response


def make_query(must_match=None):

    query = {
               "query": {
                  "bool": {
                     "must": must_match
                  }
               },
               "size": 1,
               "sort": [
                  {
                     "timestamp": {
                        "order": "desc"
                     }
                  }
               ]
            }

    return query
