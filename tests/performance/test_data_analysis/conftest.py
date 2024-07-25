import pytest
import os
from wazuh_testing.scripts.statistical_data_analyzer import load_dataframe

def pytest_addoption(parser):
    parser.addoption(
        '-b',
        '--baseline',
        action='store',
        metavar='BASELINE_PATH',
        default=None,
        type=str,
        help='Baseline file path',
    )
    parser.addoption(
        '-f',
        '--file',
        action='store',
        metavar='FILE_PATH',
        default=None,
        type=str,
        help='Data file path',
    )

def load_data(pytestconfig):
    baseline_file = pytestconfig.getoption("baseline")
    datasource_file = pytestconfig.getoption("file")

    if not baseline_file or not datasource_file:
        pytest.fail("Both baseline file and data source file must be specified")

    if not os.path.exists(baseline_file) or not os.path.exists(datasource_file):
        pytest.fail("Files specified does not exist")
    
    baseline = load_data(baseline_file)
    datasource = load_data(datasource_file)

    return baseline, datasource