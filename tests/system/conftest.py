# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import uuid
from datetime import datetime

import pytest
from numpydoc.docscrape import FunctionDoc
from py.xml import html
from system import clean_cluster_logs, remove_cluster_agents
from wazuh_testing.tools import CLUSTER_LOGS_PATH

results = dict()
report_files = []


# Clean cluster logs
@pytest.fixture(scope='function')
def clean_environment(test_infra_agents, test_infra_managers, host_manager):

    clean_cluster_logs(test_infra_agents + test_infra_managers, host_manager)

    yield
    # Remove the agent once the test has finished
    remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)


def set_report_files(files):
    if files:
        for file in files:
            report_files.append(file)


def get_report_files():
    for file in os.listdir('/tmp'):
        if 'wazuh' in file:
            report_files.append(os.path.join('/tmp', file))
    return report_files


def pytest_html_results_table_header(cells):
    cells.insert(4, html.th('Tier', class_='sortable tier', col='tier'))
    cells.insert(3, html.th('Markers'))
    cells.insert(2, html.th('Description'))
    cells.insert(1, html.th('Time', class_='sortable time', col='time'))


def pytest_html_results_table_row(report, cells):
    try:
        cells.insert(4, html.td(report.tier))
        cells.insert(3, html.td(report.markers))
        cells.insert(2, html.td(report.description))
        cells.insert(1, html.td(datetime.utcnow(), class_='col-time'))
    except AttributeError:
        pass


# HARDCODE: pytest-html generates too long file names. This temp fix is to reduce the name of
# the assets
def create_asset(
        self, content, extra_index, test_index, file_extension, mode="w"
):
    asset_file_name = "{}.{}".format(
        str(uuid.uuid4()),
        file_extension
    )
    asset_path = os.path.join(
        os.path.dirname(self.logfile), "assets", asset_file_name
    )

    if not os.path.exists(os.path.dirname(asset_path)):
        os.makedirs(os.path.dirname(asset_path))

    relative_path = os.path.join("assets", asset_file_name)

    kwargs = {"encoding": "utf-8"} if "b" not in mode else {}

    with open(asset_path, mode, **kwargs) as f:
        f.write(content)
    return relative_path


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin('html')
    outcome = yield
    report = outcome.get_result()
    documentation = FunctionDoc(item.function)

    # Add description, markers and tier to the report
    report.description = '. '.join(documentation["Summary"])
    report.tier = ', '.join(str(mark.kwargs['level']) for mark in item.iter_markers(name="tier"))
    report.markers = ', '.join(mark.name for mark in item.iter_markers() if
                               mark.name != 'tier' and mark.name != 'parametrize')

    if report.location[0] not in results:
        results[report.location[0]] = {'passed': 0, 'failed': 0, 'skipped': 0, 'xfailed': 0, 'error': 0}

    extra = getattr(report, 'extra', [])
    if report.when == 'call':
        # Apply hack to fix length filename problem
        pytest_html.HTMLReport.TestResult.create_asset = create_asset

        # Add extended information from docstring inside 'Result' section
        extra.append(pytest_html.extras.html('<div><h2>Test function details</h2></div>'))
        for section in ('Extended Summary', 'Parameters'):
            extra.append(pytest_html.extras.html(f'<div><h3>{section}</h3></div>'))
            for line in documentation[section]:
                extra.append(pytest_html.extras.html(f'<div>{line}</div>'))
        arguments = dict()

        # Add arguments of each text as a json file
        for key, value in item.funcargs.items():
            if isinstance(value, set):
                arguments[key] = list(value)
            try:
                json.dumps(value)
                arguments[key] = value
            except (TypeError, OverflowError):
                arguments[key] = str(value)
        extra.append(pytest_html.extras.json(arguments, name="Test arguments"))

        if "cluster" in report.markers:
            host_manager = getattr(item.module, "host_manager")

            for host in host_manager.get_inventory()['managers']['hosts']:
                log_path = os.path.join("/tmp", f"{host}_cluster.log")
                if os.path.exists(log_path):
                    continue
                with open(log_path, "w") as cluster_log:
                    cluster_log.write(host_manager.get_file_content(host=host, file_path=CLUSTER_LOGS_PATH))

        # Extra files to be added in 'Links' section
        files = get_report_files()
        for filepath in files:
            if os.path.isfile(filepath):
                with open(filepath, mode='r', errors='replace') as f:
                    content = f.read()
                    extra.append(pytest_html.extras.text(content, name=os.path.split(filepath)[-1]))
                os.remove(filepath)

        if not report.passed and not report.skipped:
            report.extra = extra

        if report.longrepr is not None and report.longreprtext.split()[-1] == 'XFailed':
            results[report.location[0]]['xfailed'] += 1
        else:
            results[report.location[0]][report.outcome] += 1

    elif report.outcome == 'failed':
        results[report.location[0]]['error'] += 1


class SummaryTable(html):
    class table(html.table):
        style = html.Style(border='1px solid #e6e6e6', margin='16px 0px', color='#999', font_size='12px')

    class td(html.td):
        style = html.Style(padding='5px', border='1px solid #E6E6E6', text_align='left')

    class th(html.th):
        style = html.Style(padding='5px', border='1px solid #E6E6E6', text_align='left', font_weight='bold')


def pytest_html_results_summary(prefix, summary, postfix):
    postfix.extend([SummaryTable.table(
        html.thead(
            html.tr([
                SummaryTable.th("Tests"),
                SummaryTable.th("Failed"),
                SummaryTable.th("Success"),
                SummaryTable.th("XFail"),
                SummaryTable.th("Error")]
            ),
        ),
        [html.tbody(
            html.tr([
                SummaryTable.td(k),
                SummaryTable.td(v['failed']),
                SummaryTable.td(v['passed']),
                SummaryTable.td(v['xfailed']),
                SummaryTable.td(v['error']),
            ])
        ) for k, v in results.items()])])
