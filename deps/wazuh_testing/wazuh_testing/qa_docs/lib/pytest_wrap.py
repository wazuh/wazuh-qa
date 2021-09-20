# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging


class PytestPlugin:
    """Plugin to extract information from a pytest execution.

    Attributes:
        collected: A list with the collected data from pytest execution
    """
    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        """Callback to receive the output of a pytest execution.

        Args:
            items: A list with the metadata from each test case.
        """
        for item in items:
            self.collected.append(item.nodeid)


class PytestWrap:
    """Class that wraps the execution of pytest.

    Attributes:
        plugin: A `PytestPlugin` instance.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self):
        self.plugin = PytestPlugin()

    def collect_test_cases(self, path):
        """Executes pytest in 'collect-only' mode to extract all the test cases found for a test file.

        Args:
            path: A string with the path of the test file to extract the test cases.

        Returns: A dictionary that contains the pytest parsed output.
        """
        PytestWrap.LOGGER.debug(f"Running pytest to collect test cases for '{path}'")
        pytest.main(['--collect-only', "-qq", path], plugins=[self.plugin])
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
