import os

DEFAULT_REQUIREMENTS_PATH = 'framework/requirements.txt'
DEFAULT_REPORT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'report_file.json')


def pytest_addoption(parser):
    parser.addoption('--requirements-path', action='store', default=DEFAULT_REQUIREMENTS_PATH)
    parser.addoption('--report-path', action='store', default=DEFAULT_REPORT_PATH)
