# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime

import pytest
from numpydoc.docscrape import FunctionDoc
from py.xml import html

import wazuh_testing.tools.configuration as conf
from wazuh_testing import global_parameters, logger
from wazuh_testing.logcollector import create_file_structure, delete_file_structure
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_CONF, get_service, ALERT_FILE_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor, SocketController, close_sockets
from wazuh_testing.tools.services import control_service, check_daemon_status, delete_dbs
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.mocking import create_mocked_agent, delete_mocked_agent


if sys.platform == 'win32':
    from wazuh_testing.fim import KEY_WOW64_64KEY, KEY_WOW64_32KEY, delete_registry, registry_parser, create_registry

PLATFORMS = set("darwin linux win32 sunos5".split())
HOST_TYPES = set("server agent".split())

catalog = list()
results = dict()

###############################
report_files = [LOG_FILE_PATH, WAZUH_CONF, WAZUH_LOCAL_INTERNAL_OPTIONS]


def set_report_files(files):
    if files:
        for file in files:
            report_files.append(file)


def get_report_files():
    return report_files

###############################


def pytest_runtest_setup(item):
    # Find if platform applies
    supported_platforms = PLATFORMS.intersection(mark.name for mark in item.iter_markers())
    plat = sys.platform

    if supported_platforms and plat not in supported_platforms:
        pytest.skip("Cannot run on platform {}".format(plat))

    host_type = 'agent' if 'agent' in get_service() else 'server'
    supported_types = HOST_TYPES.intersection(mark.name for mark in item.iter_markers())
    if supported_types and host_type not in supported_types:
        pytest.skip("Cannot run on wazuh {}".format(host_type))
    # Consider only first mark
    levels = [mark.kwargs['level'] for mark in item.iter_markers(name="tier")]
    if levels and len(levels) > 0:
        tiers = item.config.getoption("--tier")
        if tiers is not None and levels[0] not in tiers:
            pytest.skip(f"test requires tier level {levels[0]}")
        elif item.config.getoption("--tier-minimum") > levels[0]:
            pytest.skip(f"test requires a minimum tier level {levels[0]}")
        elif item.config.getoption("--tier-maximum") < levels[0]:
            pytest.skip(f"test requires a maximum tier level {levels[0]}")


@pytest.fixture(scope='module')
def restart_wazuh(get_configuration, request):
    # Stop Wazuh
    control_service('stop')

    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Start Wazuh
    control_service('start')


@pytest.fixture(scope='module')
def reset_ossec_log(get_configuration, request):
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)


@pytest.fixture(scope='module')
def restart_wazuh_alerts(get_configuration, request):
    # Stop Wazuh
    control_service('stop')

    # Reset alerts.json and start a new monitor
    truncate_file(ALERT_FILE_PATH)
    file_monitor = FileMonitor(ALERT_FILE_PATH)
    setattr(request.module, 'wazuh_alert_monitor', file_monitor)

    # Start Wazuh
    control_service('start')


def pytest_addoption(parser):
    parser.addoption(
        "--tier",
        action="append",
        metavar="level",
        default=None,
        type=int,
        help="only run tests with a tier level equal to 'level'",
    )
    parser.addoption(
        "--tier-minimum",
        action="store",
        metavar="minimum_level",
        default=-1,
        type=int,
        help="only run tests with a tier level greater or equal than 'minimum_level'"
    )
    parser.addoption(
        "--tier-maximum",
        action="store",
        metavar="maximum_level",
        default=sys.maxsize,
        type=int,
        help="only run tests with a tier level less or equal than 'minimum_level'"
    )
    parser.addoption(
        "--default-timeout",
        action="store",
        metavar="default_timeout",
        default=None,
        type=int,
        help="number of seconds that any timer will wait until an event is generated. This apply to all tests except"
             "those with a hardcoded timeout not depending on global_parameters.default_timeout "
             "variable from wazuh_testing package"
    )
    parser.addoption(
        "--fim-database-memory",
        action="store_true",
        help="run tests activating database memory in the syscheck configuration"
    )
    parser.addoption(
        "--gcp-project-id",
        action="store",
        metavar="gcp_project_id",
        default=None,
        type=str,
        help="run tests using Google Cloud project id"
    )
    parser.addoption(
        "--gcp-subscription-name",
        action="store",
        metavar="gcp_subscription_name",
        default=None,
        type=str,
        help="run tests using Google Cloud subscription name"
    )
    parser.addoption(
        "--gcp-credentials-file",
        action="store",
        metavar="gcp_credentials_file",
        default=None,
        type=str,
        help="run tests using json file that contains Google Cloud credentials. Introduce the path"
    )
    parser.addoption(
        "--gcp-topic-name",
        action="store",
        metavar="gcp_topic_name",
        default=None,
        type=str,
        help="run tests using Google Cloud topic name"
    )
    parser.addoption(
        "--gcp-configuration-file",
        action="store",
        metavar="gcp_configuration_file",
        default=None,
        type=str,
        help="run tests using this configuration file."
    )
    parser.addoption(
        "--fim_mode",
        action="append",
        metavar="fim_mode",
        default=[],
        type=str,
        help="run tests using a specific FIM mode"
    )
    parser.addoption(
        "--wpk_version",
        action="append",
        metavar="wpk_version",
        default=None,
        type=str,
        help="run tests using a specific WPK package version"
    )
    parser.addoption(
        "--save-file",
        action="append",
        metavar="file",
        default=[],
        type=str,
        help="add file to the HTML report"
    )
    parser.addoption(
        "--wpk_package_path",
        action="append",
        metavar="wpk_package_path",
        default=None,
        type=str,
        help="run tests using a specific WPK package path"
    )


def pytest_configure(config):
    # Register an additional marker
    config.addinivalue_line(
        "markers", "tier(level): mark test to run only if it matches tier level"
    )

    # Set default timeout only if it is passed through command line args
    default_timeout = config.getoption("--default-timeout")
    if default_timeout:
        global_parameters.default_timeout = default_timeout

    # Set fim_database_memory only if it is passed through command line args
    fim_database_memory = config.getoption("--fim-database-memory")
    if fim_database_memory:
        global_parameters.fim_database_memory = True

    # Load GCP defaults from configuration file
    gcp_configuration_file = config.getoption("--gcp-configuration-file")
    if gcp_configuration_file:
        global_parameters.gcp_configuration_file = gcp_configuration_file
    else:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        default_configuration = os.path.join(dir_path, 'test_gcloud', 'data', 'configuration.yaml')
        if os.path.exists(default_configuration):
            global_parameters.gcp_configuration_file = default_configuration

    # Set gcp_project_id only if it is passed through command line args
    gcp_project_id = config.getoption("--gcp-project-id")
    if gcp_project_id:
        global_parameters.gcp_project_id = gcp_project_id

    # Set gcp_subscription_name only if it is passed through command line args
    gcp_subscription_name = config.getoption("--gcp-subscription-name")
    if gcp_subscription_name:
        global_parameters.gcp_subscription_name = gcp_subscription_name

    # Set gcp_credentials_file only if it is passed through command line args
    gcp_credentials_file = config.getoption("--gcp-credentials-file")
    if gcp_credentials_file:
        global_parameters.gcp_credentials_file = gcp_credentials_file

    # Set gcp_topic_name only if it is passed through command line args
    gcp_topic_name = config.getoption("--gcp-topic-name")
    if gcp_topic_name:
        global_parameters.gcp_topic_name = gcp_topic_name

    # Set fim_mode only if it is passed through command line args
    mode = config.getoption("--fim_mode")
    if not mode:
        mode = ["scheduled", "whodata", "realtime"]
    global_parameters.fim_mode = mode

    # Set WPK package version
    global_parameters.wpk_version = config.getoption("--wpk_version")

    # Set files to add to the HTML report
    set_report_files(config.getoption("--save-file"))

    # Set WPK package path
    global_parameters.wpk_package_path = config.getoption("--wpk_package_path")
    if global_parameters.wpk_package_path:
        global_parameters.wpk_package_path = global_parameters.wpk_package_path


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

        # Extra files to be added in 'Links' section
        files = get_report_files()
        for filepath in files:
            if os.path.isfile(filepath):
                with open(filepath, mode='r', errors='replace') as f:
                    content = f.read()
                    extra.append(pytest_html.extras.text(content, name=os.path.split(filepath)[-1]))

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


def connect_to_sockets(request):
    """Connect to the specified sockets for the test."""
    receiver_sockets_params = getattr(request.module, 'receiver_sockets_params')

    # Create the SocketControllers
    receiver_sockets = list()
    for address, family, protocol in receiver_sockets_params:
        receiver_sockets.append(SocketController(address=address, family=family, connection_protocol=protocol))

    setattr(request.module, 'receiver_sockets', receiver_sockets)

    return receiver_sockets


def close_sockets(receiver_sockets):
    """Close the sockets connection gracefully."""
    for socket in receiver_sockets:
        try:
            # We flush the buffer before closing the connection if the protocol is TCP:
            if socket.protocol == 1:
                socket.sock.settimeout(5)
                socket.receive()  # Flush buffer before closing connection
            socket.close()
        except OSError as e:
            if e.errno == 9:
                # Do not try to close the socket again if it was reused or closed already
                pass


@pytest.fixture(scope='module')
def connect_to_sockets_module(request):
    """Module scope version of connect_to_sockets."""
    receiver_sockets = connect_to_sockets(request)

    yield receiver_sockets

    close_sockets(receiver_sockets)


@pytest.fixture(scope='function')
def connect_to_sockets_function(request):
    """Function scope version of connect_to_sockets."""
    receiver_sockets = connect_to_sockets(request)

    yield receiver_sockets

    close_sockets(receiver_sockets)


@pytest.fixture(scope='module')
def connect_to_sockets_configuration(request, get_configuration):
    """Configuration scope version of connect_to_sockets."""
    receiver_sockets = connect_to_sockets(request)

    yield receiver_sockets

    close_sockets(receiver_sockets)


@pytest.fixture(scope='module')
def configure_local_internal_options(get_local_internal_options):
    """Configure Wazuh local internal options.

    Args:
        get_local_internal_options (Fixture): Fixture that returns a dictionary with the desired local internal options.
    """
    backup_options_lines = conf.get_wazuh_local_internal_options()
    backup_options_dict = conf.local_internal_options_to_dict(backup_options_lines)

    if backup_options_dict != get_local_internal_options:
        conf.add_wazuh_local_internal_options(get_local_internal_options)

        control_service('restart')

        yield

        conf.set_wazuh_local_internal_options(backup_options_lines)

        control_service('restart')
    else:
        yield


@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""

    # Save current configuration
    backup_config = conf.get_wazuh_conf()

    # Configuration for testing
    test_config = conf.set_section_wazuh_conf(get_configuration.get('sections'))

    # Create test directories
    if hasattr(request.module, 'test_directories'):
        test_directories = getattr(request.module, 'test_directories')
        for test_dir in test_directories:
            os.makedirs(test_dir, exist_ok=True, mode=0o777)

    # Create test registry keys
    if sys.platform == 'win32':
        if hasattr(request.module, 'test_regs'):
            test_regs = getattr(request.module, 'test_regs')

            for reg in test_regs:
                match = re.match(r"(^HKEY_[a-zA-Z_]+)\\+(.+$)", reg)
                create_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_32KEY)
                create_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_64KEY)

    # Set new configuration
    conf.write_wazuh_conf(test_config)

    # Change Windows Date format to ensure TimeMachine will work properly
    if sys.platform == 'win32':
        subprocess.call('reg add "HKCU\\Control Panel\\International" /f /v sShortDate /t REG_SZ /d "dd/MM/yyyy" >nul',
                        shell=True)

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    # Set current configuration
    global_parameters.current_configuration = get_configuration

    yield

    TimeMachine.time_rollback()

    # Remove created folders (parents)
    if sys.platform == 'win32' and not hasattr(request.module, 'no_restart_windows_after_configuration_set'):
        control_service('stop')

    if hasattr(request.module, 'test_directories'):
        for test_dir in test_directories:
            shutil.rmtree(test_dir, ignore_errors=True)

    if sys.platform == 'win32':
        if hasattr(request.module, 'test_regs'):
            for reg in test_regs:
                match = re.match(r"(^HKEY_[a-zA-Z_]+)\\+(.+$)", reg)
                delete_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_32KEY)
                delete_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_64KEY)

    if sys.platform == 'win32' and not hasattr(request.module, 'no_restart_windows_after_configuration_set'):
        control_service('start')

    # Restore previous configuration
    conf.write_wazuh_conf(backup_config)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            control_service('restart')


@pytest.fixture(scope='module')
def configure_sockets_environment(request):
    """Configure environment for sockets and MITM"""
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')
    log_monitor_paths = getattr(request.module, 'log_monitor_paths')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running_condition=False)

    monitored_sockets = list()
    mitm_list = list()
    log_monitors = list()

    # Truncate logs and create FileMonitors
    for log in log_monitor_paths:
        truncate_file(log)
        log_monitors.append(FileMonitor(log))

    # Start selected daemons and monitored sockets MITM
    for daemon, mitm, daemon_first in monitored_sockets_params:
        not daemon_first and mitm is not None and mitm.start()
        control_service('start', daemon=daemon, debug_mode=True)
        check_daemon_status(
            running_condition=True,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )
        daemon_first and mitm is not None and mitm.start()
        if mitm is not None:
            monitored_sockets.append(QueueMonitor(queue_item=mitm.queue))
            mitm_list.append(mitm)

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'log_monitors', log_monitors)

    yield

    # Stop daemons and monitored sockets MITM
    for daemon, mitm, _ in monitored_sockets_params:
        mitm is not None and mitm.shutdown()
        control_service('stop', daemon=daemon)
        check_daemon_status(
            running_condition=False,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )

    # Delete all db
    delete_dbs()

    control_service('start')


@pytest.fixture(scope='function')
def configure_sockets_environment_function(request):
    """Configure environment for sockets and MITM"""
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')
    log_monitor_paths = getattr(request.module, 'log_monitor_paths')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running_condition=False)

    monitored_sockets = list()
    mitm_list = list()
    log_monitors = list()

    # Truncate logs and create FileMonitors
    for log in log_monitor_paths:
        truncate_file(log)
        log_monitors.append(FileMonitor(log))

    # Start selected daemons and monitored sockets MITM
    for daemon, mitm, daemon_first in monitored_sockets_params:
        not daemon_first and mitm is not None and mitm.start()
        control_service('start', daemon=daemon, debug_mode=True)
        check_daemon_status(
            running_condition=True,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )
        daemon_first and mitm is not None and mitm.start()
        if mitm is not None:
            monitored_sockets.append(QueueMonitor(queue_item=mitm.queue))
            mitm_list.append(mitm)

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'log_monitors', log_monitors)

    yield

    # Stop daemons and monitored sockets MITM
    for daemon, mitm, _ in monitored_sockets_params:
        mitm is not None and mitm.shutdown()
        control_service('stop', daemon=daemon)
        check_daemon_status(
            running_condition=False,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )

    # Delete all db
    delete_dbs()

    control_service('start')


@pytest.fixture(scope='module')
def put_env_variables(get_configuration, request):
    """
    Create environment variables
    """
    if hasattr(request.module, 'environment_variables'):
        environment_variables = getattr(request.module, 'environment_variables')
        for env, value in environment_variables:
            if sys.platform == 'win32':
                subprocess.call(['setx.exe', env, value, '/m'])
            else:
                os.putenv(env, value)

    yield

    if hasattr(request.module, 'environment_variables'):
        for env in environment_variables:
            if sys.platform != 'win32':
                os.unsetenv(env[0])


@pytest.fixture(scope="module")
def create_file_structure_module(get_files_list):
    """Module scope version of create_file_structure."""
    create_file_structure(get_files_list)

    yield

    delete_file_structure(get_files_list)


@pytest.fixture(scope="function")
def create_file_structure_function(get_files_list):
    """Function scope version of create_file_structure."""
    create_file_structure(get_files_list)

    yield

    delete_file_structure(get_files_list)

@pytest.fixture(scope='module')
def daemons_handler(get_configuration, request):
    """Handler of Wazuh daemons.

    It uses `daemons_handler_configuration` of each module in order to configure the behavior of the fixture.
    The  `daemons_handler_configuration` should be a dictionary with the following keys:
        daemons (list, optional): List with every daemon to be used by the module. In case of empty a ValueError
            will be raised
        all_daemons (boolean): Configure to restart all wazuh services. Default `False`.
        ignore_errors (boolean): Configure if errors in daemon handling should be ignored. This option is available
        in order to use this fixture along with invalid configuration. Default `False`

    Args:
        get_configuration (fixture): Gets the current configuration of the test.
        request (fixture): Provide information on the executing test function.
    """
    daemons = []
    ignore_errors = False
    all_daemons = False

    try:
        daemons_handler_configuration = getattr(request.module, 'daemons_handler_configuration')
        if 'daemons' in daemons_handler_configuration and not all_daemons:
            daemons = daemons_handler_configuration['daemons']
            if not daemons or (type(daemons) == list and len(daemons) == 0):
                logger.error('Daemons list is not set')
                raise ValueError

        if 'all_daemons' in daemons_handler_configuration:
            logger.debug(f"Wazuh control set to {daemons_handler_configuration['all_daemons']}")
            all_daemons = daemons_handler_configuration['all_daemons']

        if 'ignore_errors' in daemons_handler_configuration:
            logger.debug(f"Ignore error set to {daemons_handler_configuration['ignore_errors']}")
            ignore_errors = daemons_handler_configuration['ignore_errors']

    except AttributeError as daemon_configuration_not_set:
        logger.error('daemons_handler_configuration is not set')
        raise daemon_configuration_not_set

    try:
        if all_daemons:
            logger.debug('Restarting wazuh using wazuh-control')
            # Restart daemon instead of starting due to legacy used fixture in the test suite.
            control_service('restart')
        else:
            for daemon in daemons:
                logger.debug(f"Restarting {daemon}")
                # Restart daemon instead of starting due to legacy used fixture in the test suite.
                control_service('restart', daemon=daemon)

    except ValueError as value_error:
        logger.error(f"{str(value_error)}")
        if not ignore_errors:
            raise value_error
    except subprocess.CalledProcessError as called_process_error:
        logger.error(f"{str(called_process_error)}")
        if not ignore_errors:
            raise called_process_error

    yield

    if all_daemons:
        logger.debug('Stopping wazuh using wazuh-control')
        control_service('stop')
    else:
        for daemon in daemons:
            logger.debug(f"Stopping {daemon}")
            control_service('stop', daemon=daemon)


@pytest.fixture(scope='function')
def file_monitoring(request):
    """Fixture to handle the monitoring of a specified file.

    It uses the variable `file_to_monitor` to determinate the file to monitor. Default `LOG_FILE_PATH`

    Args:
        request (fixture): Provide information on the executing test function.
    """
    if hasattr(request.module, 'file_to_monitor'):
        file_to_monitor = getattr(request.module, 'file_to_monitor')
    else:
        file_to_monitor = LOG_FILE_PATH

    logger.debug(f"Initializing file to monitor to {file_to_monitor}")

    file_monitor = FileMonitor(file_to_monitor)
    setattr(request.module, 'log_monitor', file_monitor)

    yield

    truncate_file(file_to_monitor)
    logger.debug(f"Trucanted {file_to_monitor}")


@pytest.fixture(scope='module')
def configure_local_internal_options_module(request):
    """Fixture to configure the local internal options file.

    It uses the test variable local_internal_options. This should be
    a dictionary wich keys and values corresponds to the internal option configuration, For example:
    local_internal_options = {'monitord.rotate_log': '0', 'syscheck.debug': '0' }
    """
    try:
        local_internal_options = getattr(request.module, 'local_internal_options')
    except AttributeError as local_internal_configuration_not_set:
        logger.debug('local_internal_options is not set')
        raise local_internal_configuration_not_set

    backup_local_internal_options = conf.get_local_internal_options_dict()

    logger.debug(f"Set local_internal_option to {str(local_internal_options)}")
    conf.set_local_internal_options_dict(local_internal_options)

    yield

    logger.debug(f"Restore local_internal_option to {str(backup_local_internal_options)}")
    conf.set_local_internal_options_dict(backup_local_internal_options)


@pytest.fixture(scope='module')
def mock_agent_module():
    """
    Fixture to create a mocked agent in wazuh databases
    """
    agent_id = create_mocked_agent(name="mocked_agent")

    yield agent_id

    delete_mocked_agent(agent_id)
