# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from py.xml import html


def pytest_addoption(parser):
    # Get command line options
    parser.addoption("--artifacts_path", action="store")
    parser.addoption("--n_workers", action="store")
    parser.addoption("--n_agents", action="store")


def pytest_html_report_title(report):
    report.title = 'Wazuh Cluster performance tests'


# HTML report
class HTMLStyle(html):
    class body(html.body):
        style = html.Style(background_color='#F0F0EE')

    class table(html.table):
        style = html.Style(border='2px solid #005E8C', margin='16px 0px', color='#005E8C',
                           font_size='15px')

    class colored_td(html.td):
        style = html.Style(color='#005E8C', padding='5px', border='2px solid #005E8C', text_align='center',
                           white_space='pre-wrap', font_size='14px')

    class td(html.td):
        style = html.Style(padding='5px', border='2px solid #005E8C', text_align='left',
                           white_space='pre-wrap', font_size='14px')

    class th(html.th):
        style = html.Style(color='#0094ce', padding='5px', border='2px solid #005E8C', text_align='center',
                           font_weight='bold', font_size='15px')

    class h1(html.h1):
        style = html.Style(color='#0094ce')

    class h2(html.h2):
        style = html.Style(color='#0094ce')

    class h3(html.h3):
        style = html.Style(color='#0094ce')


def pytest_html_results_table_header(cells):
    # Remove links header
    cells.pop()


def pytest_html_results_table_row(report, cells):
    # Remove links column
    cells.pop()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Define HTML style
    pytest_html = item.config.pluginmanager.getplugin('html')
    pytest_html.html.body = HTMLStyle.body
    pytest_html.html.table = HTMLStyle.table
    pytest_html.html.th = HTMLStyle.th
    pytest_html.html.td = HTMLStyle.td
    pytest_html.html.h1 = HTMLStyle.h1
    pytest_html.html.h2 = HTMLStyle.h2
    pytest_html.html.h3 = HTMLStyle.h3

    outcome = yield
    report = outcome.get_result()
    extra = getattr(report, 'extra', [])

    if report.when == 'teardown':
        # Create table with data of exceeded thresholds
        if item.module.exceeded_thresholds:
            extra.append(pytest_html.extras.html("<table>"))
            extra.append(
                pytest_html.extras.html(f"<tr><th>{'</th><th>'.join(item.module.exceeded_thresholds[0].keys())}</tr>"))
            for exc_th in item.module.exceeded_thresholds:
                extra.append(pytest_html.extras.html(
                    f"<tr><th>{'</th><th>'.join(str(value) for value in exc_th.values())}</tr>"))
            extra.append(pytest_html.extras.html("</table>"))
        report.extra = extra
