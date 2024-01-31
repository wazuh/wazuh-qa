'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, these tests will check if macOS 'log stream' processes are properly managed by
       the logcollector. Log data collection is the real-time process of making sense out of the records
       generated by servers or devices. This component can receive logs through text files or Windows
       event logs. It can also directly receive logs via remote syslog which is useful
       for firewalls and other such devices.

components:
    - logcollector

suite: macos

targets:
    - agent

daemons:
    - wazuh-logcollector

os_platform:
    - macos

os_version:
    - macOS Catalina
    - macOS Sierra

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html

tags:
    - logcollector_macos
'''
import os
import pytest
import platform
import signal
import time

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import search_process, control_service
from wazuh_testing.tools.utils import retry

pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

macos_sierra = True if str(platform.mac_ver()[0]).startswith('10.12') else False
macos_log_init_timeout = 5
# Marks


# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=[''])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="function")
def restart_required_logcollector_function():
    """Get configurations from the module."""
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


def test_independent_log_process(get_configuration, configure_environment, file_monitoring,
                                 restart_required_logcollector_function):
    '''
    description: Check if the independent execution of log processes (external to Wazuh) is not altered when
                 the Wazuh agent is started or stopped. For this purpose, the test will configure a 'localfile'
                 section using the macOS settings. Once the logcollector is started, it will check if the
                 'monitoring' event is triggered, indicating that the logcollector starts to monitor the macOS
                 logs. Then, the test will stop the Wazuh agent, launch a new log process and start it again.
                 After this, it will verify that the log process is active by checking its PID, stopping the agent,
                 and verifying that the log process remains active. Finally, the test will kill the log process
                 launched and start the agent again to restore the initial estate of the system.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_required_logcollector_function:
            type: fixture
            brief: Restart the Wazuh agent.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.

    assertions:
        - Verify that the logcollector starts monitoring the macOS ULS log messages.
        - Verify that the Wazuh agent does not kill independent log processes when it is started.
        - Verify that the Wazuh agent does not kill independent log processes when it is stopped.

    input_description: A configuration template (test_macos_log_process) is contained in an external YAML
                       file (wazuh_macos_format_basic.yaml). That template is combined with a test case
                       defined in the module. That include configuration settings
                       for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'Monitoring macOS logs with.*'
        - PID of the log process launched.

    tags:
        - logs
    '''
    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=macos_logcollector_monitored,
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


def test_macos_log_process_stop(get_configuration, configure_environment, file_monitoring,
                                restart_required_logcollector_function):
    '''
    description: Check if the 'wazuh-logcollector' daemon stops the 'log' and 'script' process when the Wazuh agent
                 or logcollector are stopped. Two processes would run on the macOS system when the logcollector is
                 configured to get macOS system logs. The log process and the script (only for Sierra) one. If the
                 logcollector process is finished or the Wazuh agent is stopped, those processes must stop.
                 For this purpose, the test will configure a 'localfile' section using the macOS settings. Once
                 the logcollector is started, it will check if the 'monitoring' event is triggered, indicating that
                 the logcollector starts to monitor the macOS logs. Then, the test will verify that the 'log' and
                 'script' processes are running, stop the 'wazuh-logcollector' daemon, verify that the 'log' and
                 'script' processes are stopped, and start it again. Finally, the test will repeat the previous
                 steps, but stopping and starting the Wazuh agent instead of the 'wazuh-logcollector' daemon.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_required_logcollector_function:
            type: fixture
            brief: Restart the Wazuh agent.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.

    assertions:
        - Verify that the logcollector starts monitoring the macOS ULS log messages.
        - Verify that the 'log' and 'script' processes are finished when the 'wazuh-logcollector' daemon is stopped.
        - Verify that the 'log' and 'script' processes are finished when the wazuh agent is stopped.

    input_description: A configuration template (test_macos_log_process) is contained in an external YAML
                       file (wazuh_macos_format_basic.yaml). That template is combined with a test case
                       defined in the module. That include configuration settings
                       for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'Monitoring macOS logs with.*'

    tags:
        - logs
    '''
    process_to_stop = ['log', 'script'] if macos_sierra else ['log']

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=macos_logcollector_monitored,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    check_process_status(process_to_stop, running=True, stage='at start')

    control_service('stop', daemon='wazuh-logcollector')
    check_process_status(process_to_stop, running=False, stage='after stop logcollector')
    control_service('start', daemon='wazuh-logcollector')

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=macos_logcollector_monitored,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    check_process_status(process_to_stop, running=True, stage='after start logcollector')

    control_service('stop', daemon='wazuh-logcollector')
    check_process_status(process_to_stop, running=False, stage='after stop agent')


def test_macos_log_process_stop_suddenly_warning(get_configuration, configure_environment, file_monitoring,
                                                 restart_required_logcollector_function):
    '''
    description: Check if the 'wazuh-logcollector' daemon generates an error event when the 'log stream' process
                 is stopped. In macOS Sierra, this test also checks if when the log process ends, then the 'script'
                 process also ends. For this purpose, the test will configure a 'localfile' section using the macOS
                 settings. Once the logcollector is started, it will check if the 'monitoring' event is triggered,
                 indicating that the logcollector starts to monitor the macOS logs. Then, the test will verify that
                 the 'log' and 'script' processes are running. After this, it will send a signal to terminate that
                 processes and check if they are closed. Finally, the test will verify that a logcollector error
                 event is generated when the log or script process is not detected.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_required_logcollector_function:
            type: fixture
            brief: Restart the Wazuh agent.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
       
    assertions:
        - Verify that the logcollector starts monitoring the macOS ULS log messages.
        - Verify that the logcollector detects when the 'log' or 'script' process is closed.

    input_description: A configuration template (test_macos_log_process) is contained in an external YAML
                       file (wazuh_macos_format_basic.yaml). That template is combined with a test case
                       defined in the module. That include configuration settings
                       for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'Monitoring macOS logs with.*'
        - r'macOS "log stream" process exited'

    tags:
        - logs
    '''
    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=macos_logcollector_monitored,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    time.sleep(macos_log_init_timeout)

    process_to_kill = ['log', 'script'] if macos_sierra else ['log']

    check_process_status(process_to_kill, running=True, stage='at start')

    for killed_process in process_to_kill:
        log_processes = search_process(killed_process)
        log_process_id = log_processes[0]['pid']
        os.kill(int(log_process_id), signal.SIGTERM)

        check_process_status(process_to_kill, running=False, stage='at start')

        macos_logcollector_monitored = logcollector.callback_log_stream_exited_error()
        log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=macos_logcollector_monitored,
                          error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

        control_service('restart', daemon='wazuh-logcollector')