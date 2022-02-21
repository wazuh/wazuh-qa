import pytest


def pytest_collectreport(report):
    if report.failed:
        pass
