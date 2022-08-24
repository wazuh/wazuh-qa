# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import requests
from http import HTTPStatus

from wazuh_testing.tools.utils import retry


@retry(Exception, attempts=3, delay=5)
def get_alert_indexer_api(query, credentials, ip_address, index='wazuh-alerts-4.x-*'):
    """Get an alert from the wazuh-indexer API

      Make a request to the wazuh-indexer API to get the last indexed alert that matches the values passed in
      must_match.

      Args:
          ip_address (str): wazuh-indexer IP address.
          index (str): Index in which to search for the alert.
          query (dict): Query to send to the API.
          credentials(dict): wazuh-indexer credentials.

      Returns:
          `obj`(map): Search results
     """
    url = f"https://{ip_address}:9200/{index}/_search?"

    response = requests.get(url=url, params={'pretty': 'true'}, json=query, verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'], credentials['password']))

    if '"hits" : [ ]' in response.text:
        raise Exception('Alert not indexed')
    elif response.status_code != HTTPStatus.OK:
        raise Exception(f"The request wasn't successful.\nActual response: {response.text}")

    return response


def delete_index_api(credentials, ip_address, index='wazuh-alerts-4.x-*'):
    """Delete indices from wazuh-indexer using its API.

      Make a request to the wazuh-indexer API to delete indices that match a given name.

      Args:
          ip_address (str): wazuh-indexer IP address.
          index (str): Name of the index to be deleted.
          credentials(dict): wazuh-indexer credentials.

      Returns:
          obj(class): `Response <Response>` object
          obj(class): `NoneType` object
    """
    url = f"https://{ip_address}:9200/"
    authorization = requests.auth.HTTPBasicAuth(credentials['user'], credentials['password'])

    response = requests.delete(url=url+index, params={'pretty': 'true'}, verify=False, auth=authorization)

    if response.status_code != HTTPStatus.OK:
        raise Exception(f"The index(es) have not been deleted successfully. Actual response {response.text}")

    return response


def make_query(must_match):
    """Create a query according to the values passed in must_match.

     Args:
         must_match (list): Values to be matched with the indexed alert.

     Returns:
         dict: Fully formed query.
     """
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
