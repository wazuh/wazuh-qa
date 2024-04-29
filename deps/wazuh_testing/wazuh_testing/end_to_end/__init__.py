# Copyright (C) 2015, Wazuh Inc
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import logging
import os
import requests

from dataclasses import dataclass
from http import HTTPStatus
from tempfile import gettempdir
from typing import Any, Callable, List

from wazuh_testing.tools.utils import retry


fetched_alerts_json_path = os.path.join(gettempdir(), 'alerts.json')
VD_E2E_TIMEOUT_SYSCOLLECTOR_SCAN = 130

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
    query.

    Args:
        ip_address (str): wazuh-indexer IP address.
        index (str): Index in which to search for the alert.
        query (dict): Query to send to the API.
        credentials(dict): wazuh-indexer credentials.

    Returns:
        `obj`(map): Search results
     """
    url = f"https://{ip_address}:9200/{index}/_search?"

    response = requests.get(url=url, params={'pretty': 'true'}, json=query,
                            verify=False,
                            auth=requests.auth.HTTPBasicAuth(credentials['user'],
                                                             credentials['password']))

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
    authorization = requests.auth.HTTPBasicAuth(credentials['user'],
                                                credentials['password'])

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
    """A data class representing evidence.

    Attributes:
        name (str): The name of the evidence.
        value (Any): The value of the evidence.
        debug (bool, optional): Indicates whether the evidence is for debugging, for verbose evidences.
                                Defaults to False.
    """
    name: str
    value: Any
    debug: bool = False

    def collect_evidence(self, evidences_directory: str):
        """Collects evidence and stores it in the specified directory.

        Args:
            evidences_directory (str): The directory where evidence files will be stored.
        """
        try:
            with open(os.path.join(evidences_directory, self.name), 'w') as evidence_file:
                self._write_to_file(evidence_file)
        except Exception as e:
            self._log_error(e)

    def _write_to_file(self, evidence_file):
        """Writes evidence to a file.

        Args:
            evidence_file: File object to write evidence to.
        """
        if isinstance(self.value, (dict, list)):
            json.dump(self.value, evidence_file, indent=4)
        else:
            evidence_file.write(str(self.value))

    def _log_error(self, e):
        """Logs error occurred while writing evidence.

        Args:
            e: The exception that occurred.
        """
        logging.error(f"Error while writing evidence {self.name}: {e}")

    def dict(self):
        """Returns the evidence as a dictionary.

        Returns:
            dict: A dictionary representation of the evidence.
        """
        return {self.name: self.value}


class Check:
    """A class representing a check to be performed, including validation and reporting.

    Attributes:
        name (str): The name of the check.
        assert_function (Callable): The function used for assertion.
        expected_evidences (List[str] | None): List of expected evidence names to perform the validation.
            Default is None.
        result: The result of the check.
        evidences: List of collected evidence objects.
    """
    def __init__(self, name: str, assert_function: Callable,
                 expected_evidences: List[str] = None):
        """Initializes a check with the given name, assertion function, and expected evidences.

        Args:
            name (str): The name of the check.
            assert_function (Callable): The function used for assertion.
            expected_evidences (List[str] | None, optional): List of expected evidence names. Defaults to None.
        """
        self.name = name
        self.result = None
        self.assert_function = assert_function
        self.expected_evidences = expected_evidences if expected_evidences else []
        self.evidences = []

    def __str__(self) -> str:
        """Returns a string representation of the check.

        Returns:
            str: A string containing the check's name and result.
        """
        return self.report_check()

    def validate(self, evidences: List[Evidence] = None) -> bool:
        """Validates the check using the provided evidences.

        Args:
            evidences (List[Evidence] | None, optional): List of evidence objects. Defaults to None.

        Returns:
            bool: True if validation succeeds, False otherwise.

        Raises:
            ValueError: If provided evidences do not contains the expected ones.
        """

        evidences = [] if not evidences else evidences

        provided_evidences_names = [evidence.name for evidence in evidences]
        provided_evidences_expected = [evidence for evidence in evidences
                                       if evidence.name in self.expected_evidences]

        if len(self.expected_evidences) != len(provided_evidences_expected):
            raise ValueError('Evidences should match the expected ones.\n' +
                             f"Expected evidences: {self.expected_evidences}."
                             f"Evidences found: {provided_evidences_names}")

        self.result = self.assert_function(*[evidence.value for evidence in provided_evidences_expected])
        self.evidences = evidences

        logging.error(f"Marked check {self.name} result to {self.result} with evidences {provided_evidences_names}")

        return self.result

    def get_result(self):
        """Gets the result of the check.

        Returns:
            Any: The result of the check.

        Raises:
            ValueError: If the check has not been executed yet.
        """
        if self.result is None:
            raise ValueError(f"Check {self.name} has not been executed yet")

        return self.result

    def report_check(self):
        """Generates a report message for the check.

        Returns:
            str: A report message indicating whether the check succeeded or failed.
        """
        message = f"Check {self.name} "
        message += f"failed. Evidences ({self.expected_evidences}) " + \
            "can be found in the report." if not self.get_result() else "succeeded"
        message += '\n'

        return message

    def collect_evidences(self, evidences_directory: str, collect_debug_evidences: bool = False):
        """Collects evidences for the check.

        Args:
            evidences_directory (str): The directory where evidence files will be stored.
            collect_debug_evidences (bool, optional): If True, collects debug evidence. Defaults to False.
        """
        for evidence in self.evidences:
            if evidence.debug and not collect_debug_evidences:
                continue

            evidence.collect_evidence(evidences_directory)


class TestResult:
    """A data class representing a test result.

    Attributes:
        test_name (str): The name of the test.
        checks (List[Check]): List of checks of the test, default is an empty list.
    """
    def __init__(self, test_name: str, checks: List[Check] = None):
        """Initializes a test suite with the given name and checks.

        Args:
            test_name (str): The name of the test suite.
            checks (List[Check] | None, optional): List of checks. Defaults to None.
        """
        self.test_name = test_name
        self.checks = checks if checks else []

    def __str__(self) -> str:
        """Returns a string representation of the test suite.

        Returns:
            str: A string containing the test suite's name and report.
        """
        return self.report()

    def add_check(self, check: Check) -> None:
        """Adds a check to the test suite.

        Args:
            check (Check): The check to be added.
        """
        self.checks.append(check)

    def get_test_result(self) -> bool:
        """Gets the result of the test suite.

        Returns:
            bool: True if all checks passed, False otherwise.
        """
        return all([check.result for check in self.checks])

    def collect_evidences(self, evidences_directory: str,
                          collect_verbose_evidences: bool = False,
                          collect_evidences_for_passed_checks: bool = False) -> None:
        """Collects evidences for the checks in the test suite.

        Args:
            evidences_directory (str): The directory where evidence files will be stored.
            collect_verbose_evidences (bool, optional): If True, collects verbose evidences. Defaults to False.
            collect_evidences_for_passed_checks (bool, optional): If True, collects evidences for passed checks as well.
                                                                  Defaults to False.
        """
        for check in self.checks:
            if check.get_result() and not collect_evidences_for_passed_checks:
                continue
            check.collect_evidences(evidences_directory, collect_verbose_evidences)

    def report(self) -> str:
        """Generates a report message for the test suite.

        Returns:
            str: A report message indicating whether the test suite succeeded or failed,
                 along with individual check reports.
        """
        message = f"\nTest {self.test_name} "
        message += "failed\n\n" if not self.get_test_result() else "succeeded:\n\n-----\n"

        if not self.get_test_result():
            for check in self.checks:
                message += check.report_check()

            message += "-----\n"

        return message

    def validate_check(self, check_name: str, evidences: List[Evidence]) -> bool:
        """Validates a specific check in the test suite.

        Args:
            check_name (str): The name of the check to validate.
            evidences (List[Evidence]): List of evidence objects.

        Returns:
            bool: True if validation succeeds, False otherwise.

        Raises:
            ValueError: If the check with the given name is not found in the test suite.
        """
        check = self.get_check(check_name)

        return check.validate(evidences)

    def get_check(self, check_name: str) -> Check:
        """ Retrieves a specific check from the test suite.

        Args:
            check_name (str): The name of the check to retrieve.

        Returns:
            Check: The check object.

        Raises:
            ValueError: If the check with the given name is not found in the test suite.
        """
        for check in self.checks:
            if check.name == check_name:
                return check
        else:
            raise ValueError(f"Check {check_name} not found in test {self.test_name}")
