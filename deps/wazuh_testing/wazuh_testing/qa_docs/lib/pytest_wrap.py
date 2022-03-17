# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys

from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging


class PytestPlugin:
    """Plugin to extract information from a pytest execution.

    Attributes:
        collected (list): A list with the collected data from pytest execution
    """
    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        """Callback to receive the output of a pytest execution.

        Args:
            items (list): A list with the metadata from each test case.
        """
        for item in items:
            self.collected.append(item.nodeid)


class PytestWrap:
    """Class that wraps the execution of pytest.

    Attributes:
        plugin (PytestPlugin): A `PytestPlugin` instance.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self):
        self.plugin = PytestPlugin()

    def collect_test_cases(self, path):
        """Execute pytest in 'collect-only' mode to extract all the test cases found for a module file.

        Args:
            path (str): A string with the path of the module file to extract the test cases.

        Returns:
            outpout (dict): A dictionary that contains the pytest parsed output.
        """
        PytestWrap.LOGGER.debug(f"Running pytest to collect test cases for '{path}'")

        # Redirect the stdout to 'null' so --collect-only does not log anything
        default_stdout = sys.stdout
        no_stdout = open(os.devnull, 'w')
        sys.stdout = no_stdout
        pytest.main(['--collect-only', "-qq", path], plugins=[self.plugin])
        sys.stdout = default_stdout
        output = {}

        for item in self.plugin.collected:
            tmp = item.split("::")
            tmp = tmp[1].split("[")
            test = tmp[0]

            if test not in output:
                output[test] = []

            if len(tmp) >= 2:
                tmp = tmp[1].split("]")
                test_case = tmp[0]
                output[test].append(test_case)

        return output
