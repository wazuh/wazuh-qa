DEFAULT_REFERENCE = 'master'
DEFAULT_REPOSITORY = 'wazuh'


def pytest_addoption(parser):
    parser.addoption("--reference", action="store", default=DEFAULT_REFERENCE,
                     help=f"Set the reference used. Default: {DEFAULT_REFERENCE}")
    parser.addoption("--repo", action="store", default=DEFAULT_REPOSITORY,
                     help=f"Set the repository used. Default: {DEFAULT_REPOSITORY}")
