import pytest

class PytestPlugin:
    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            self.collected.append(item.nodeid)

class TestCaseParser:
    def __init__(self):
        self.plugin = PytestPlugin()

    def collect(self, path):
        pytest.main(['--collect-only', path], plugins=[self.plugin])
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
