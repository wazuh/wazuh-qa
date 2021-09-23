DEFAULT_BRANCH = 'master'
DEFAULT_REPOSITORY = 'wazuh'


def pytest_addoption(parser):
    parser.addoption('--branch', action='store', default=DEFAULT_BRANCH)
    parser.addoption('--repo', action='store', default=DEFAULT_REPOSITORY)
