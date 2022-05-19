# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from py.xml import html
import re
from numpydoc.docscrape import FunctionDoc


def pytest_addoption(parser):
    # Get command line options
    parser.addoption(
        "--artifacts_path",
        action="store",
        type=str,
        help="Path where information of all cluster nodes can be found (logs, stats CSVs, etc)."
    )


# Fixtures
@pytest.fixture()
def artifacts_path(pytestconfig):
    return pytestconfig.getoption("artifacts_path")


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


def pytest_html_report_title(report):
    report.title = 'Wazuh cluster reliability tests'


def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Description'))
    cells.pop()


def pytest_html_results_table_row(report, cells):
    try:
        cells.insert(2, html.td(report.description))
        cells.pop()
    except AttributeError:
        pass


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    def atoi(text):
        return int(text) if text.isdigit() else text

    # Define HTML style
    pytest_html = item.config.pluginmanager.getplugin('html')
    pytest_html.html.body = HTMLStyle.body
    pytest_html.html.table = HTMLStyle.table
    pytest_html.html.th = HTMLStyle.th
    pytest_html.html.td = HTMLStyle.td
    pytest_html.html.h1 = HTMLStyle.h1
    pytest_html.html.h2 = HTMLStyle.h2
    pytest_html.html.h3 = HTMLStyle.h3
    pytest_html.html.p = HTMLStyle.b

    documentation = FunctionDoc(item.function)

    outcome = yield
    report = outcome.get_result()
    extra = getattr(report, 'extra', [])
    report.description = '. '.join(documentation["Summary"])

    if report.when == 'teardown':
        # Attach error logs per each node in the 'test_cluster_error_logs' test.
        if report.head_line == 'test_cluster_error_logs' and item.module.nodes_with_errors:
            extra.append(pytest_html.extras.html("<h2>Error logs</h2>"))
            # Keys are human/natural sorted.
            for node, logs in sorted(item.module.nodes_with_errors.items(),
                                     key=lambda d: [atoi(c) for c in re.split(r'(\d+)', d[0])]):
                extra.append(pytest_html.extras.html(f'<p><b>{node}:</b>\n' + '\n'.join(
                    log_line.decode() for log_line in logs) + '</p>'))
            extra.append(pytest_html.extras.html("</p><h2>Test output</h2>"))

        # Attach wrong order logs per each node in the 'test_check_logs_order' tests (both master's and workers').
        elif report.head_line == 'test_check_logs_order_workers' or report.head_line == 'test_check_logs_order_master' \
                and item.module.incorrect_order:
            extra.append(pytest_html.extras.html("<h2>Wrong worker logs order</h2>" if 'workers' in report.head_line
                                                 else "<h2>Wrong master logs order</h2>"))
            # Keys are human/natural sorted.
            for key in sorted(item.module.incorrect_order.keys(),
                              key=lambda d: [atoi(c) for c in re.split(r'(\d+)', d)]):
                extra.append(pytest_html.extras.html(f"<p><b>{key}:</b>\n"))
                for failed_task in item.module.incorrect_order[key]:
                    extra.append(pytest_html.extras.html('<b> - Log type:</b> {log_type}\n'
                                                         '<b>   Expected logs:</b> {expected_logs}\n'
                                                         '<b>   Found log:</b> {found_log}'.format(**failed_task)))
            extra.append(pytest_html.extras.html("</p><h2>Test output</h2>"))

        # Attach repeated Integrity synchronizations per each node in the 'test_cluster_sync' test.
        elif report.head_line == 'test_cluster_sync' and item.module.repeated_syncs:
            extra.append(pytest_html.extras.html("<h2>Repeated Integrity synchronizations</h2>"))
            output = []
            # Keys are human/natural sorted.
            for worker, values in sorted(item.module.repeated_syncs.items(),
                                         key=lambda d: [atoi(c) for c in re.split(r'(\d+)', d[0])]):
                output.append('<b>{worker} - Log found {repeat_counter} times in a row:</b>\n'
                              '{log}'.format(**values, worker=worker))
            extra.append(pytest_html.extras.html('<p>' + '\n\n'.join(output) + '</p>'))
            extra.append(pytest_html.extras.html("</p><h2>Test output</h2>"))

        # Attach nodes were some tasks were repeted or not completed in the requested order from the
        # 'test_cluster_task_order' test.
        elif report.head_line == 'test_cluster_task_order' and item.module.incorrect_order:
            for key in item.module.incorrect_order:
                extra.append(pytest_html.extras.html("<h2>Wrong task order.</h2>"))
                extra.append(pytest_html.extras.html(f"<p><b>Concatenated tasks '{key}' and "
                                                     f"'{item.module.incorrect_order[key]['child_task']}'"
                                                     f" failed due to {item.module.incorrect_order[key]['status']}"
                                                     f" logs:\n\t{item.module.incorrect_order[key]['log']}</b>"))

            extra.append(pytest_html.extras.html("</p><h2>Test output</h2>"))

        report.extra = extra
