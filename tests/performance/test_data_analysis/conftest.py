import pytest
import os
import pytest_html
from contextlib import redirect_stdout
from wazuh_testing.tools.performance.statistical_data_analyzer import DataLoader

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
        '--confidence_level',
        action='store',
        metavar='CONFIDENCE_LEVEL',
        default=95,
        type=float,
        help='Level of confidence for the analysis',
    )


@pytest.fixture
def load_data(pytestconfig):
    """Fixture to convert the CSV files passed in Dataframes and to load them in 
    the test together with the other parameters.
    
    Args:
        pytestconfig: that returns the :class:`_pytest.config.Config` object.
    
    Returns:
        baseline: Dataframe with the baseline data.
        datasource: Dataframe with the data for comparison.
        threshold: threshold value for change detection.
        conf_level: level of confidence por the statistic analysis.
    """
    baseline_file = pytestconfig.getoption("baseline")
    datasource_file = pytestconfig.getoption("datasource")
    conf_level = pytestconfig.getoption("confidence_level")

    if not (0 <= conf_level <= 100):
        pytest.fail(f"The value of confidence_level is not valid")

    return baseline_file, datasource_file, conf_level


@pytest.fixture
def config(pytestconfig):
    """Fixture to process the YML file with the elements to be analyzed
    during the test.

    Args:
        pytestconfig: that returns the :class:`_pytest.config.Config` object.
    Returns:
        config: Dict with the items to be analyzed.
    """
    config_file = pytestconfig.getoption("items_yaml")

    if not config_file:
        pytest.fail(f"File with the items to analyze must be specified")

    return config_file


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    report.extra = getattr(report, 'extra', [])

    if report.when == 'call' and report.failed:
        baseline_file, datasource_file, _ = item.funcargs['load_data']
        items_yaml_path = item.config.getoption("items_yaml")

        data_loader = DataLoader(baseline_file, datasource_file, items_yaml_path)
        output = data_loader.print_dataframes_stats()
        
        report_dir = os.path.dirname(item.config.option.htmlpath)
        assets_dir = os.path.join(report_dir, "assets")
        if not os.path.exists(assets_dir):
            os.makedirs(assets_dir)

        test_name = item.name
        log_file = os.path.join(assets_dir, f"{test_name}_stats.log")
        with open(log_file, 'w') as file:
            file.write(output)

        relative_log_file = os.path.relpath(log_file, report_dir)
        report.extra.append(pytest_html.extras.url(relative_log_file, name='Statistical comparison'))
