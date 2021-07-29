DEFAULT_REQUIREMENTS_PATH = 'framework/requirements.txt'


def pytest_addoption(parser):
    parser.addoption("--path", action="store", default=DEFAULT_REQUIREMENTS_PATH)
