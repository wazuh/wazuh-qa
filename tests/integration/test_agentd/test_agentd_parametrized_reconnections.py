'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       The objective is to check how the 'wazuh-agentd' daemon behaves when there are delays
       between connection attempts to the 'wazuh-remoted' daemon using TCP and UDP protocols.
       The 'wazuh-remoted' program is the server side daemon that communicates with the agents.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
    - wazuh-remoted

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
from datetime import datetime, timedelta
import os
import platform
import pytest
from time import sleep

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import CLIENT_KEYS_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

params = [
    # Different parameters on UDP
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 1, 'RETRY_INTERVAL': 1, 'ENROLL': 'no'},
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 5, 'RETRY_INTERVAL': 5, 'ENROLL': 'no'},
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 10, 'RETRY_INTERVAL': 4, 'ENROLL': 'no'},
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 3, 'RETRY_INTERVAL': 12, 'ENROLL': 'no'},
    # Different parameters on TCP
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 3, 'RETRY_INTERVAL': 3, 'ENROLL': 'no'},
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 5, 'RETRY_INTERVAL': 5, 'ENROLL': 'no'},
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 10, 'RETRY_INTERVAL': 10, 'ENROLL': 'no'},
    # Enrollment enabled
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 2, 'RETRY_INTERVAL': 2, 'ENROLL': 'yes'},
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 5, 'RETRY_INTERVAL': 5, 'ENROLL': 'yes'},
]

case_ids = [f"{x['PROTOCOL']}_max-retry={x['MAX_RETRIES']}_interval={x['RETRY_INTERVAL']}_enroll={x['ENROLL']}".lower()
            for x in params]

metadata = params
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)
log_monitor_paths = []
receiver_sockets_params = []
monitored_sockets_params = []
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
authd_server = AuthdSimulator('127.0.0.1', key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)
remoted_server = None


@pytest.fixture
def teardown():
    yield

    global remoted_server
    if remoted_server is not None:
        remoted_server.stop()


def set_debug_mode():
    """Set debug2 for agentd in local internal options file."""
    if platform.system() == 'win32' or platform.system() == 'Windows':
        local_int_conf_path = os.path.join(WAZUH_PATH, 'local_internal_options.conf')
        debug_line = 'windows.debug=2\n'
    else:
        local_int_conf_path = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
        debug_line = 'agent.debug=2\n'
    with open(local_int_conf_path) as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n' + debug_line)


set_debug_mode()


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=case_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def configure_authd_server(request):
    """Initialize a simulated authd connection."""
    authd_server.start()
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)
    authd_server.clear()
    yield
    authd_server.shutdown()


@pytest.fixture(scope="function")
def start_authd(request):
    """Enable authd to accept connections and perform enrollments."""
    authd_server.set_mode("ACCEPT")
    authd_server.clear()


@pytest.fixture(scope="function")
def stop_authd(request):
    """Disable authd to accept connections and perform enrollments."""
    authd_server.set_mode("REJECT")


@pytest.fixture(scope="function")
def clean_keys(request):
    """Clear the agent's client.keys file."""
    truncate_file(CLIENT_KEYS_PATH)
    sleep(1)


@pytest.fixture(scope="function")
def delete_keys(request):
    """Remove the agent's client.keys file."""
    os.remove(CLIENT_KEYS_PATH)
    sleep(1)


@pytest.fixture(scope="function")
def set_keys(request):
    """Write to client.keys file the agent's enrollment details."""
    with open(CLIENT_KEYS_PATH, 'w+') as f:
        f.write("100 ubuntu-agent any TopSecret")
    sleep(1)


@pytest.fixture(scope="function")
def start_agent(request):
    """Start Wazuh's agent."""
    control_service('start')


@pytest.fixture(scope="function")
def stop_agent(request):
    """Stop Wazuh's agent."""
    control_service('stop')


def clean_logs():
    """Clear the log file."""
    truncate_file(LOG_FILE_PATH)


def wait_notify(line):
    """Callback function to wait for agent checkins to the manager."""
    if 'Sending keep alive:' in line:
        return line
    return None


def wait_server_rollback(line):
    """Callback function to wait until the agent cannot connect to any server."""
    if "Unable to connect to any server" in line:
        return line
    return None


def wait_connect(line):
    """Callback function to wait for the agent to try to connect to a server."""
    if 'Trying to connect to server' in line:
        return line
    return None


def count_retry_mesages():
    """Count number of attempts to connect to server and enrollments made from log file.

    Returns:
        (int , int): Tuple with connection attempts and enrollments.
    """
    connect = 0
    enroll = 0
    with open(LOG_FILE_PATH) as log_file:
        log_lines = log_file.read().splitlines()
        for line in log_lines:
            if 'Trying to connect to server' in line:
                connect += 1
            if 'Valid key received' in line:
                enroll += 1
            if "Unable to connect to any server" in line:
                return connect, enroll
    return connect, enroll


def wait_enrollment(line):
    """Callback function to wait for enrollment."""
    if 'Valid key received' in line:
        return line
    return None


def wait_unable_to_connect(line):
    """Callback function to wait until the agent cannot connect to a server."""
    if 'connect_server(): ERROR: (1216):' in line:
        return line
    return None


def change_timeout(new_value):
    """Set agent.recv_timeout for agentd in local internal options file.

    The above option sets the maximum number of seconds to wait
    for server response from the TCP client socket.

    Args:
        new_value (int): Number of seconds (between 1 and 600).
    """
    new_timeout = 'agent.recv_timeout=' + new_value
    if platform.system() == 'win32' or platform.system() == 'Windows':
        local_int_conf_path = os.path.join(WAZUH_PATH, 'local_internal_options.conf')
    else:
        local_int_conf_path = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == new_timeout:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n' + new_timeout)


change_timeout('5')


def parse_time_from_log_line(log_line):
    """Create a datetime object from a date in a string.

    Args:
        log_line (str): String with date.

    Returns:
        datetime: datetime object with the parsed time.
    """
    data = log_line.split(" ")
    (year, month, day) = data[0].split("/")
    (hour, minute, second) = data[1].split(":")
    log_time = datetime(year=int(year), month=int(month), day=int(day), hour=int(hour), minute=int(minute),
                        second=int(second))
    return log_time


# Tests
"""
This test covers different options of delays between server connection attempts:
-Different values of max_retries parameter
-Different values of retry_interval parameter
-UDP/TCP connection
-Enrollment between retries
"""


def test_agentd_parametrized_reconnections(configure_authd_server, start_authd, stop_agent, set_keys,
                                           configure_environment, get_configuration, teardown):
    '''
    description: Check how the agent behaves when there are delays between connection
                 attempts to the server. For this purpose, different values for
                 'max_retries' and 'retry_interval' parameters are tested.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - start_authd:
            type: fixture
            brief: Enable the 'wazuh-authd' daemon to accept connections and perform enrollments.
        - stop_agent:
            type: fixture
            brief: Stop Wazuh's agent.
        - set_keys:
            type: fixture
            brief: Write to 'client.keys' file the agent's enrollment details.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that when the 'wazuh-agentd' daemon initializes, it connects to
          the 'wazuh-remoted' daemon of the manager before reaching the maximum number of attempts.
        - Verify the successful enrollment of the agent if the auto-enrollment option is enabled.
        - Verify that the rollback feature of the server works correctly.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Valid key received'
        - r'Trying to connect to server'
        - r'Unable to connect to any server'

    tags:
        - simulator
        - ssl
        - keys
    '''
    DELTA = 1
    RECV_TIMEOUT = 5
    ENROLLMENT_SLEEP = 20
    LOG_TIMEOUT = 30

    global remoted_server

    PROTOCOL = protocol = get_configuration['metadata']['PROTOCOL']
    RETRIES = get_configuration['metadata']['MAX_RETRIES']
    INTERVAL = get_configuration['metadata']['RETRY_INTERVAL']
    ENROLL = get_configuration['metadata']['ENROLL']

    control_service('stop')
    clean_logs()
    log_monitor = FileMonitor(LOG_FILE_PATH)
    remoted_server = RemotedSimulator(protocol=PROTOCOL, client_keys=CLIENT_KEYS_PATH)
    control_service('start')

    # 2 Check for unsuccessful connection retries in Agentd initialization
    interval = INTERVAL
    if PROTOCOL == 'udp':
        interval += RECV_TIMEOUT

    if ENROLL == 'yes':
        total_retries = RETRIES + 1
    else:
        total_retries = RETRIES

    for retry in range(total_retries):
        # 3 If auto enrollment is enabled, retry check enrollment and retries after that
        if ENROLL == 'yes' and retry == total_retries - 1:
            # Wait successfully enrollment
            try:
                log_monitor.start(timeout=20, callback=wait_enrollment)
            except TimeoutError as err:
                raise AssertionError("No successful enrollment after retries!")
            last_log = parse_time_from_log_line(log_monitor.result())

            # Next retry will be after enrollment sleep
            interval = ENROLLMENT_SLEEP

        try:
            log_monitor.start(timeout=interval + LOG_TIMEOUT, callback=wait_connect)
        except TimeoutError as err:
            raise AssertionError("Connection attempts took too much!")
        actual_retry = parse_time_from_log_line(log_monitor.result())
        if retry > 0:
            delta_retry = actual_retry - last_log
            # Check if delay was applied
            assert delta_retry >= timedelta(seconds=interval - DELTA), "Retries to quick"
            assert delta_retry <= timedelta(seconds=interval + DELTA), "Retries to slow"
        last_log = actual_retry

    # 4 Wait for server rollback
    try:
        log_monitor.start(timeout=30, callback=wait_server_rollback)
    except TimeoutError as err:
        raise AssertionError("Server rollback took too much!")

    # 5 Check amount of retries and enrollment
    (connect, enroll) = count_retry_mesages()
    assert connect == total_retries
    if ENROLL == 'yes':
        assert enroll == 1
    else:
        assert enroll == 0

    return
