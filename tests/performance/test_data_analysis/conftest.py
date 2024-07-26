import pytest
import os
import yaml
from wazuh_testing.scripts.statistical_data_analyzer import load_dataframe

def pytest_addoption(parser):
    parser.addoption(
        '--baseline',
        action='store',
        metavar='BASELINE_PATH',
        default=None,
        type=str,
        help='Baseline file path',
    )
    parser.addoption(
        '--datasource',
        action='store',
        metavar='DATASOURCE_PATH',
        default=None,
        type=str,
        help='Data source file path',
    )
    parser.addoption(
        '--items_yaml',
        action='store',
        metavar='ITEMS_YAML_PATH',
        default=None,
        type=str,
        help='Items yaml file path',
    )
    parser.addoption(
        '--threshold',
        action='store',
        metavar='THRESHOLD',
        default=None,
        type=float,
        help='Threshold for comparison',
    )
    parser.addoption(
        '--confidence_level',
        action='store',
        metavar='CONFIDENCE_LEVEL',
        default=None,
        type=float,
        help='Level of confidence for the analysis',
    )

@pytest.fixture
def load_data(pytestconfig):
    baseline_file = pytestconfig.getoption("baseline")
    datasource_file = pytestconfig.getoption("datasource")
    threshold = pytestconfig.getoption("threshold")
    conf_level = pytestconfig.getoption("confidence_level")

    if not baseline_file or not datasource_file:
        pytest.fail("Both baseline file and data source file must be specified")

    if not os.path.exists(baseline_file) or not os.path.exists(datasource_file):
        pytest.fail("Files specified does not exist")
    
    baseline = load_dataframe(baseline_file)
    datasource = load_dataframe(datasource_file)

    return baseline, datasource, threshold, conf_level

@pytest.fixture
def config(pytestconfig):
    config_file = pytestconfig.getoption("items_yaml")

    if not config_file:
        pytest.fail("File with the items to analyze must be specified")

    if not os.path.exists(config_file):
        pytest.fail(f"Items yaml file '{config_file}' does not exist")

    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    return config
