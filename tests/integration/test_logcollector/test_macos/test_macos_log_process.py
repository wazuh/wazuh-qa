# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import platform
import signal

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import search_process, control_service
from wazuh_testing.tools.utils import retry


macos_sierra = True if str(platform.mac_ver()[0]).startswith('10.12') else False

# Marks

pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=[''])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def restart_required_logcollector_function():
    """Get configurations from the module."""
    control_service('restart')


@pytest.fixture(scope="module")
def up_wazuh_after_module():

    yield
    control_service('restart')


@retry(AssertionError, attempts=5, delay=2, delay_multiplier=1)
def check_process_status(process_list, running=True, stage=''):
    """Assert that some processes are running or not.

        This will check a list of processes and asserts that all of them are running or not based on the arguments.

        Args:
            process_list (string list): the list of processes to check
            running (boolean): if the processes are expected to be running or not
            stage (string): in case of failure this string is appended at the end of the error message and indicated
                in which moment was the error produced (for example: after agent restart)

        Raises:
            AssertionError: if the condition is not met
    """
    expected_process = 1 if running else 0
    is_running_msg = 'is not running' if running else 'is running'
    for process in process_list:
        log_processes = search_process(process)
        assert len(log_processes) == expected_process, f'Process {process} {is_running_msg} {stage}.'


def test_independent_log_process(get_configuration, configure_environment, restart_required_logcollector_function, file_monitoring, up_wazuh_after_module):
    """Check that independent execution of log processes (external to Wazuh) are not altered because of the Wazuh agent.

       Launches a log process and start Wazuh, check that the independent log process keep running along with the one
       started by Wazuh. Stops Wazuh and check that the independent process is still running.

        Raises:
            TimeoutError: If the expected callback is not generated.
    """
    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    control_service('stop')
    check_process_status(['log'], running=False, stage='after stop agent')

    # Run a log stream in background
    os.system('log stream&')

    log_processes = search_process('log')
    independent_log_pid = log_processes[0]['pid']

    control_service('start', 'wazuh-logcollector')

    assert any(x['pid'] == independent_log_pid for x in search_process('log')), 'The independent log process is dead ' \
                                                                                'after starting Wazuh agent '
    control_service('stop', 'wazuh-logcollector')

    assert any(x['pid'] == independent_log_pid for x in search_process('log')), 'The independent log process is dead ' \
                                                                                'after stopping Wazuh agent '
    os.kill(int(independent_log_pid), signal.SIGTERM)

    control_service('start')

def test_macos_log_process_stop(get_configuration, configure_environment, restart_required_logcollector_function,  file_monitoring, up_wazuh_after_module):
    """Check if logcollector stops the log and script process when Wazuh agent or logcollector stop.

    There are two process that would run on macOS system when logcollector is configured to get
    macOS system logs. The log process and the script (only for Sierra) one. If logcollector process
    finish or the agent is stopped, those process must stop.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    process_to_stop = ['log', 'script'] if macos_sierra else ['log']

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    check_process_status(process_to_stop, running=True, stage='at start')

    control_service('stop', daemon='wazuh-logcollector')
    check_process_status(process_to_stop, running=False, stage='after stop logcollector')
    control_service('start', daemon='wazuh-logcollector')

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    check_process_status(process_to_stop, running=True, stage='after start logcollector')

    control_service('stop', daemon='wazuh-logcollector')
    check_process_status(process_to_stop, running=False, stage='after stop agent')

    control_service('start')


def test_macos_log_process_stop_suddenly_warning(restart_logcollector_required_daemons_package, get_configuration, configure_environment,restart_required_logcollector_function,file_monitoring, up_wazuh_after_module):
    """Check if logcollector alerts when `log stream` process has stopped.

    In Sierra this tests also checks that, if log process ends, then script process also ends and the other way around.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    process_to_kill = ['log', 'script'] if macos_sierra else ['log']

    check_process_status(process_to_kill, running=True, stage='at start')

    for killed_process in process_to_kill:
        log_processes = search_process(killed_process)
        log_process_id = log_processes[0]['pid']
        os.kill(int(log_process_id), signal.SIGTERM)

        check_process_status(process_to_kill, running=False, stage='at start')

        macos_logcollector_monitored = logcollector.callback_log_stream_exited_error()
        log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

        control_service('restart', daemon='wazuh-logcollector')

    control_service('start')
