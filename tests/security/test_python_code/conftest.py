DEFAULT_DIRECTORIES_TO_CHECK = 'framework/,api/,wodles/'
DEFAULT_DIRECTORIES_TO_EXCLUDE = 'tests/,test/'
DEFAULT_CONFIDENCE_LEVEL = 'MEDIUM'
DEFAULT_SEVERITY_LEVEL = 'LOW'


def pytest_addoption(parser):
    parser.addoption("--check_directories", action="store", default=DEFAULT_DIRECTORIES_TO_CHECK)
    parser.addoption("--exclude_directories", action="store", default=DEFAULT_DIRECTORIES_TO_EXCLUDE)
    parser.addoption("--confidence", action="store", default=DEFAULT_CONFIDENCE_LEVEL)
    parser.addoption("--severity", action="store", default=DEFAULT_SEVERITY_LEVEL)
