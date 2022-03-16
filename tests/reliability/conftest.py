# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json

import pytest

from wazuh_testing import global_parameters


def pytest_addoption(parser):
    parser.addoption(
        '--report',
        action='store',
        metavar='REPORT_PATH',
        default=None,
        type=str,
        help='JSON report path',
    )
    parser.addoption(
        '--target-hosts',
        action='store',
        metavar='TARGET_HOSTS',
        default='agents,managers',
        type=str,
        help='Comma separated list of target hosts',
    )
    parser.addoption(
        '--target-daemons',
        action='store',
        metavar='TARGET_DAEMONS',
        default=None,
        type=str,
        help='Comma separated list of target daemons',
    )


def pytest_configure(config):
    report_path = config.getoption('--report')
    if report_path:
        global_parameters.report_path = report_path

    targets_hosts = config.getoption('--target-hosts')
    if targets_hosts:
        global_parameters.target_hosts = targets_hosts.split(',')
    else:
        global_parameters.target_hosts = []

    targets_daemons = config.getoption('--target-daemons')
    if targets_daemons:
        global_parameters.target_daemons = targets_daemons.split(',')
    else:
        global_parameters.target_daemons = None


@pytest.fixture(scope='session')
def get_report():
    if not global_parameters.report_path:
        raise ValueError("No option named 'report'")
    try:
        with open(global_parameters.report_path) as report:
            yield json.loads(report.read())
    except Exception:
        raise ValueError('Error in report read, no valid JSON format was provided')
