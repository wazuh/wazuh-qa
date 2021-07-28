DEFAULT_BRANCH = 'master'


def pytest_addoption(parser):
    parser.addoption("--branch", action="store", default=DEFAULT_BRANCH)
