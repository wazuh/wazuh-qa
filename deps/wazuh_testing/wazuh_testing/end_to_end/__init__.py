# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import requests
import logging
import json
from dataclasses import dataclass
from typing import Any, List
from http import HTTPStatus
from tempfile import gettempdir

from wazuh_testing.tools.utils import retry


fetched_alerts_json_path = os.path.join(gettempdir(), 'alerts.json')

base_path = {
    'linux': '/var/ossec',
    'windows': r'C:\Program Files (x86)\ossec-agent',
    'macos': '/Library/Ossec'
}
configuration_filepath_os = {
    'linux': os.path.join(base_path['linux'], 'etc', 'ossec.conf'),
    'windows': os.path.join(base_path['windows'], 'ossec.conf'),
    'macos': os.path.join(base_path['macos'], 'etc', 'ossec.conf')
}
logs_filepath_os = {
    'linux': os.path.join(base_path['linux'], 'logs', 'ossec.log'),
    'windows': os.path.join(base_path['windows'], 'ossec.log'),
    'macos': os.path.join(base_path['macos'], 'logs', 'ossec.log')
}


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


@dataclass
class Evidence:
    name: str
    value: Any
    debug: bool = False

    def collect_evidence(self, evidences_directory: str):
        try:
            with open(os.path.join(evidences_directory, self.name), 'w') as evidence_file:
                if isinstance(self.value, dict) or isinstance(self.value, list):
                    evidence_file.write(json.dumps(self.value, indent=4))
                else:
                    evidence_file.write(self.value)
        except PermissionError as e:
            logging.error(f"Error while writing evidence {self.name}: {e}")
        except FileNotFoundError as e:
            logging.error(f"Error while writing evidence {self.name}: {e}")
        except Exception as e:
            logging.error(f"Error while writing evidence {self.name}: {e}")

    def dict(self):
        return {self.name: self.value}

class Check:
    def __init__(self, name: str, assert_function: callable, expected_evidences: list = None):
        self.name = name
        self.result = None
        self.assert_function = assert_function
        self.expected_evidences = expected_evidences if expected_evidences else []
        self.evidences = []

    def __str__(self) -> str:
        return self.report_check()

    def validate(self, evidences: List[Evidence] = None) -> bool:
        provided_evidences = [evidence for evidence in evidences if evidence.name in self.expected_evidences]
        provided_evidences_names = [evidence.name for evidence in provided_evidences]

        if provided_evidences_names != self.expected_evidences:
            raise ValueError('Evidences should match the expected ones.\n'
                             f"Expected evidences: {self.expected_evidences}. Evidences found: {provided_evidences}")

        self.result = self.assert_function(*[evidence.value for evidence in provided_evidences])
        self.evidences = evidences

        logging.error(f"Marked check {self.name} result to {self.result} with evidences {provided_evidences}")

        return self.result

    def get_result(self):
        if self.result is None:
            raise ValueError("Check has not been executed yet")
        
        return self.result

    def report_check(self):
        message = f"Check {self.name} "
        message += f"failed\n. Evidences ({self.expected_evidences}) " \
                    "can be found in the report.\n\n" if not self.get_result() else "succeeded\n"

        return message

    def collect_evidences(self, evidences_directory: str, debug: bool = False):
        for evidence in self.evidences:
            if evidence.debug and not debug:
                continue

            evidence.collect_evidence(evidences_directory)


class TestResult:
    def __init__(self, test_name: str, checks: List[Check]=None):
        self.test_name = test_name
        self.checks = checks if checks else []

    def __str__(self) -> str:
        return self.report()
    
    def add_check(self, check: Check):
        self.checks.append(check)

    def get_test_result(self):
        return all([check.result for check in self.checks])

    def collect_evidences(self, evidences_directory: str, collect_verbose_evidences: bool = False,
                          collect_evidences_for_passed_checks: bool = False):
        for check in self.checks:
            if check.get_result() and not collect_evidences_for_passed_checks:
                continue
            
            check.collect_evidences(evidences_directory, collect_verbose_evidences)

    def report(self):
        message = f"\nTest {self.test_name} "
        message += "failed\n\n" if not self.get_test_result() else "succeeded:\n\n-----\n"

        if not self.get_test_result():
            for check in self.checks:
                message += check.report_check()

            message += "-----\n"

        return message

    def get_check(self, check_name: str):
        for check in self.checks:
            if check.name == check_name:
                return check
        else:
            raise ValueError(f"Check {check_name} not found in test {self.test_name}")

