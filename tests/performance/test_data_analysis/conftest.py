# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Pytest configuration for Statistical Data Analysis tests

This module contains fixtures that allow to obtain the test input data and to manage the final report.

Functions:
    - pytest_addoption: defines the input parameters when running the test.
    - get_data: fixture that gets the CSV files and the confidence level passed as parameters.
    - config: fixture that gets the YAML file with the configuration of the test.
    - pytest_runtest_makereport: generates the necessary information in the final test report.
"""

import pytest
import os
import pytest_html

from typing import Generator, Tuple
from statistical_data_analyzer import DataLoader


def pytest_addoption(parser: pytest.Parser) -> None:
    """Function that collects the parameters used to execute the test.

    Args:
        parser (pytest.Parser): the parser for command line arguments and ini-file values.
    """
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
def get_data(pytestconfig: pytest.Config) -> Tuple[str, str, float]:
    """Fixture that collects the CSV files and the confidence level passed by parameters to the test.

    Args:
        pytestconfig (pytest.Config): returns the :class:`_pytest.config.Config` object.

    Returns:
        baseline (str): path to the baseline data file.
        datasource (str): path to the incoming data file.
        conf_level (float): level of confidence por the statistic analysis.
    """
    baseline_file = pytestconfig.getoption("baseline")
    datasource_file = pytestconfig.getoption("datasource")
    conf_level = pytestconfig.getoption("confidence_level")

    if not (0 <= conf_level <= 100):
        pytest.fail(f"The value of confidence_level is not valid")

    return baseline_file, datasource_file, conf_level


@pytest.fixture
def config(pytestconfig: pytest.Config) -> str:
    """Fixture that collects the YML file with the elements to be analyzed
    during the test.

    Args:
        pytestconfig (pytest.Config): returns the :class:`_pytest.config.Config` object.

    Returns:
        config (str): path to the YML file.
    """
    config_file = pytestconfig.getoption("items_yaml")

    if not config_file:
        pytest.fail(f"File with the items to analyze must be specified")

    return config_file


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Generator[None, None, None]:
    """Add to the final Pytest report a file with the statistical comparison tables."""
    outcome = yield
    report = outcome.get_result()
    report.extra = getattr(report, 'extra', [])

    if report.when == 'call' and report.failed:
        if 'get_data' in item.funcargs:
            baseline_file, datasource_file, _ = item.funcargs['get_data']
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
