DEFAULT_DIRECTORIES_TO_CHECK = 'framework/,api/,wodles/'
DEFAULT_DIRECTORIES_TO_EXCLUDE = 'tests/,test/'
DEFAULT_CONFIDENCE_LEVEL = 'MEDIUM'
DEFAULT_SEVERITY_LEVEL = 'LOW'


def pytest_addoption(parser):
    parser.addoption("--check_directories", action="store", default=DEFAULT_DIRECTORIES_TO_CHECK,
                     help=f"Set the directories to check, this must be a string with the directory name. "
                          f"If more than one is indicated, they must be separated with comma. "
                          f"Default: {DEFAULT_DIRECTORIES_TO_CHECK}")
    parser.addoption("--exclude_directories", action="store", default=DEFAULT_DIRECTORIES_TO_EXCLUDE,
                     help=f"Set the directories to exclude, this must be a string with the directory name. "
                          f"If more than one is indicated, they must be separated with comma. "
                          f"Default: {DEFAULT_DIRECTORIES_TO_EXCLUDE}")
    parser.addoption("--confidence", action="store", default=DEFAULT_CONFIDENCE_LEVEL,
                     help=f"Set the minimum value of confidence of the Bandit scan. "
                          f"This value must be 'UNDEFINED', 'LOW', 'MEDIUM' or 'HIGH'. "
                          f"Default: {DEFAULT_CONFIDENCE_LEVEL}")
    parser.addoption("--severity", action="store", default=DEFAULT_SEVERITY_LEVEL,
                     help=f"Set the minimum value of severity of the Bandit scan. "
                          f"This value must be 'UNDEFINED', 'LOW', 'MEDIUM' or 'HIGH'. "
                          f"Default: {DEFAULT_SEVERITY_LEVEL}")
