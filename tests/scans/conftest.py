DEFAULT_BRANCH = 'master'
DEFAULT_REPOSITORY = 'wazuh'


def pytest_addoption(parser):
    parser.addoption("--reference", action="store", default=DEFAULT_BRANCH,
                     help=f"Set the repository reference(branch or commit). Default: {DEFAULT_REPOSITORY}")
    parser.addoption("--repo", action="store", default=DEFAULT_REPOSITORY,
                     help=f"Set the repository used. Default: {DEFAULT_BRANCH}")
