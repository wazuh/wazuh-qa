DEFAULT_BRANCH = 'master'
DEFAULT_REPOSITORY = 'wazuh'
DEFAULT_REQUIREMENTS_PATH = 'framework/requirements.txt'


def pytest_addoption(parser):
    parser.addoption("--branch", action="store", default=DEFAULT_BRANCH)
    parser.addoption("--repo", action="store", default=DEFAULT_REPOSITORY)
    parser.addoption("--path", action="store", default=DEFAULT_REQUIREMENTS_PATH)
