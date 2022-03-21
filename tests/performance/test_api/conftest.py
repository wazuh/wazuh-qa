# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os.path import join, dirname, realpath
from time import sleep

import pytest
import requests
from py.xml import html
from yaml import safe_load

from wazuh_testing.api import get_api_details_dict

results = dict()
configuration = safe_load(open(join(dirname(realpath(__file__)), 'data', 'configuration.yaml')))['configuration']


@pytest.fixture(scope='module')
def set_api_test_environment(request):
    kwargs = dict()
    kwargs.update({'host': configuration['host'], 'port': configuration['port']})

    api_details = get_api_details_dict(**kwargs)

    # Set a longer token expiration timeout
    token_time_endpoint = f"{api_details['base_url']}/security/config"
    headers = api_details['auth_headers']
    response = requests.put(token_time_endpoint, headers=headers, json={'auth_token_exp_timeout': 999999}, verify=False)

    assert response.status_code == 200, f'Failed to set API token expiration timeout. Response: {response.json()}'

    # Ask for a new token and set it
    setattr(request.module, 'api_details', get_api_details_dict(**kwargs))


@pytest.fixture(scope='function')
def api_healthcheck(request):
    yield

    user_properties = getattr(request.node, 'user_properties')
    # Check if there was a restart
    if len(user_properties) > 4 and user_properties[4][1]:
        active = False
        api_details = getattr(request.module, 'api_details')
        while not active:
            try:
                status = None
                status = requests.get(api_details['base_url'], headers=api_details['auth_headers'],
                                      verify=False).status_code
            except Exception:
                pass
            finally:
                if status == 200:
                    active = True
                else:
                    sleep(5)


def pytest_html_report_title(report):
    report.title = 'Wazuh API performance tests'


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
    cells[1] = html.th('Method')
    cells.insert(2, html.th('Endpoint'))
    cells.insert(3, html.th('Parameters'))
    cells.insert(4, html.th('Body'))
    cells.insert(5, html.th('Restart'))

    # Remove links
    cells.pop()


def pytest_html_results_table_row(report, cells):
    try:
        # Replace test name for method
        cells[1] = HTMLStyle.colored_td(report.user_properties[1][1].upper())
        cells[2] = HTMLStyle.colored_td(report.user_properties[0][1])
        cells[3] = HTMLStyle.colored_td(str(report.user_properties[2][1]))
        cells.append(HTMLStyle.colored_td(str(report.user_properties[3][1])))
        cells.append(HTMLStyle.colored_td(u'\u2713' if len(report.user_properties) > 4 and report.user_properties[4][1] else ''))
        cells.append(HTMLStyle.colored_td(f'{report.duration:.3f} s'))

    except AttributeError:
        pass


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

    if report.location[0] not in results:
        results[report.location[0]] = {'passed': 0, 'failed': 0, 'skipped': 0, 'xfailed': 0, 'error': 0}

    if report.when == 'call':
        if report.longrepr is not None and report.longreprtext.split()[-1] == 'XFailed':
            results[report.location[0]]['xfailed'] += 1
        else:
            results[report.location[0]][report.outcome] += 1

    elif report.outcome == 'failed':
        results[report.location[0]]['error'] += 1


def pytest_html_results_summary(prefix, summary, postfix):
    postfix.extend([HTMLStyle.table(
        html.thead(
            html.tr([
                HTMLStyle.th("Tests"),
                HTMLStyle.th("Success"),
                HTMLStyle.th("Failed"),
                HTMLStyle.th("XFail"),
                HTMLStyle.th("Error")]
            ),
        ),
        [html.tbody(
            html.tr([
                HTMLStyle.td(k),
                HTMLStyle.td(v['passed']),
                HTMLStyle.td(v['failed']),
                HTMLStyle.td(v['xfailed']),
                HTMLStyle.td(v['error']),
            ])
        ) for k, v in results.items()])])


def pytest_collection_modifyitems(session, config, items):
    # Add test configuration as metadata (environment table)
    config._metadata = configuration

    # Add each test_case metadata as user_properties for its item
    for item in items:
        item.user_properties.extend([(key, value) for key, value in item.callspec.params['test_case'].items()])
