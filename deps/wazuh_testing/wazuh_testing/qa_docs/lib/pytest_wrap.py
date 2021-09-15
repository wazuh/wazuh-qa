"""
brief: Wazuh pytest wrapper.
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 02, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import pytest
import logging

class PytestPlugin:
    """
    brief: Plugin to extract information from a pytest execution.
    """
    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        """
        brief: Callback to receive the output of a pytest execution.
        """
        for item in items:
            self.collected.append(item.nodeid)

class PytestWrap:
    """
    brief: Class that wraps the execution of pytest.
    """
    def __init__(self):
        self.plugin = PytestPlugin()

    def collect_test_cases(self, path):
        """
        brief: "Executes pytest in 'collect-only' mode to extract all the test cases found for a test file.
        args:
            - "path (string): Path of the test file to extract the test cases.
        returns: "dictionary: The output of pytest parsed into a dictionary"
        """
        logging.debug(f"Running pytest to collect testcases for '{path}'")
        pytest.main(['--collect-only', "-qq", path], plugins=[self.plugin])
        output = {}
        for item in self.plugin.collected:
            tmp = item.split("::")
            tmp = tmp[1].split("[")
            test = tmp[0]
            if not test in output:
                output[test] = []
            if len(tmp) >= 2:
                tmp = tmp[1].split("]")
                test_case = tmp[0]
                output[test].append(test_case)
        return output
