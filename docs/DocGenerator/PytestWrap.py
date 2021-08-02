import pytest
import logging

class PytestPlugin:
    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            self.collected.append(item.nodeid)

class PytestWrap:
    def __init__(self):
        self.plugin = PytestPlugin()

    def collect_test_cases(self, path):
        logging.debug(f"Running pytest to collect testcases for '{path}'")
        pytest.main(['--collect-only', "-qq", path], plugins=[self.plugin])
        output = {}
        for item in self.plugin.collected:
            tmp = item.split("::")
            file = tmp[0]
            tmp = tmp[1].split("[")
            test = tmp[0]
            if not test in output:
                output[test] = []
            if len(tmp) >= 2:
                tmp = tmp[1].split("]")
                test_case = tmp[0]
                output[test].append(test_case)
        return output
