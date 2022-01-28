import pytest
import os
import json
from wazuh_testing import global_parameters, logger


def pytest_addoption(parser):
    parser.addoption(
        "--report-path",
        action="store",
        metavar="REPORT_PATH",
        default=None,
        type=str,
        help="Report path",
    )


def pytest_configure(config):
    report_path = config.getoption("--report-path")
    if report_path:
        global_parameters.report_path = report_path


@pytest.fixture(scope='session')
def get_report():
    try:
        with open(global_parameters.report_path) as report:
            global_parameters.report = json.loads(report.read())
    except Exception:
        raise ValueError("Not provided a valid report path")
