# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import math
import json
import stat
import os
import tempfile
from time import sleep
from datetime import datetime
from socket import AF_UNIX, SHUT_RDWR, SOCK_STREAM, SOCK_DGRAM, socket

import pytest

import wazuh_testing.logcollector as logcollector
from wazuh_testing import global_parameters
from wazuh_testing.tools import monitoring, file
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=1)]

# Configuration
DAEMON_NAME = "wazuh-logcollector"
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_location_custom_sockets_conf.yaml')
temp_dir = tempfile.gettempdir()
log_test_path = os.path.join(temp_dir, 'test.log')
mode = "tcp"

# Batch sizes of lines to add to the test log (powers of 2)
lines_batch = [2 ** x for x in range(0, 12)]

local_internal_options = {
    'logcollector.debug': 2,
    'logcollector.state_interval': 5,
    'monitord.rotate_log': 0
}

parameters = []
for x in range(0, 12):
    parameters.append({'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
                       'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'tcp'})
    parameters.append({'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
                       'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'udp'})

# parameters = [
#     {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
#      'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'tcp'},
#     # {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
#     #  'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'udp'}
# ]

metadata = []
for x in range(0, 12):
    metadata.append({'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket',
                     'socket_path': '/var/run/custom.sock', 'mode': 'tcp', 'lines_batch': 2 ** x,
                     'log_line': "Jan  1 00:00:00 localhost test[0]: log line"})
    metadata.append({'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket',
                     'socket_path': '/var/run/custom.sock', 'mode': 'udp', 'lines_batch': 2 ** x,
                     'log_line': "Jan  1 00:00:00 localhost test[0]: log line"})

# metadata = [
#     {'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket',
#      'socket_path': '/var/run/custom.sock', 'mode': 'tcp',
#      'log_line': "Jan  1 00:00:00 localhost test[0]: log line"},
#     # {'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket',
#     #  'socket_path': '/var/run/custom.sock', 'mode': 'udp',
#     #  'log_line': "Jan  1 00:00:00 localhost test[0]: log line"}
# ]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"target_socket:{x['socket_name']}_mode:{x['mode']}" for x in metadata]


def get_logcollector_data_sending_stats(log_path, named_socket):
    """Returns the statistics of a log monitored by logcollector.

    For this purpose, it parses the wazuh-logcollector.state file and retrieves the data.
    See:
    https://documentation-dev.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html

    Args:
        log_path (str): Path of the log from which the statistics are to be obtained.
        named_socket (str): Target socket name.

    Returns:
        dict: Dictionary with the statistics.
    """
    statistics_file_path = '/var/ossec/var/run/wazuh-logcollector.state'
    # Wait until the statistics file becomes available
    for _ in range(global_parameters.default_timeout):
        if os.path.isfile(statistics_file_path):
            break
        else:
            sleep(1)

    with open('/var/ossec/var/run/wazuh-logcollector.state', 'r') as json_file:
        data = json.load(json_file)
        global_files = data['global']['files']
        global_start = data['global']['start']
        global_end = data['global']['end']
        global_start_seconds = datetime.strptime(data['global']['start'], '%Y-%m-%d %H:%M:%S').time().second
        global_end_seconds = datetime.strptime(data['global']['end'], '%Y-%m-%d %H:%M:%S').time().second
        interval_files = data['interval']['files']
        interval_start = data['interval']['start']
        interval_end = data['interval']['end']
        interval_start_seconds = datetime.strptime(data['interval']['start'], '%Y-%m-%d %H:%M:%S').time().second
        interval_end_seconds = datetime.strptime(data['interval']['end'], '%Y-%m-%d %H:%M:%S').time().second
        stats = {'global_events': 0, 'global_drops': 0,
                 'global_start': global_start, 'global_end': global_end,
                 'global_start_seconds': global_start_seconds, 'global_end_seconds': global_end_seconds,
                 'interval_events': 0, 'interval_drops': 0,
                 'interval_start': interval_start, 'interval_end': interval_end,
                 'interval_start_seconds': interval_start_seconds, 'interval_end_seconds': interval_end_seconds}
        # Global statistics
        for g_file in global_files:
            if g_file['location'] == log_path:
                stats['global_events'] = g_file['events']
                targets = g_file['targets']
                for t in targets:
                    if t['name'] == named_socket:
                        stats['global_drops'] = t['drops']
        # Interval statistics
        for i_file in interval_files:
            if i_file['location'] == log_path:
                stats['interval_events'] = i_file['events']
                targets = i_file['targets']
                for t in targets:
                    if t['name'] == named_socket:
                        stats['interval_drops'] = t['drops']
    return stats


def get_next_stats(current_stats, log_path, named_socket):
    """Return the next statistics to be written to the "wazuh-logcollector.state" file.

    Args:
        current_stats (dict): Dictionary with the current statistics.
        log_path (str): Path of the log from which the statistics are to be obtained.
        named_socket (str): Target socket name.

    Returns:
        dict: Dictionary with the next statistics.

    Raises:
          TimeoutError: If the next statistics could not be obtained according to the interval
                        defined by "logcollector.state_interval"
    """
    state_interval_seconds = local_internal_options['logcollector.state_interval']
    seconds_next_interval = (int(current_stats['interval_end_seconds']) + state_interval_seconds) % 60
    for _ in range(0, state_interval_seconds + 1):
        next_stats = get_logcollector_data_sending_stats(log_path, named_socket)
        if int(next_stats['interval_end_seconds']) != seconds_next_interval:
            sleep(1)
        else:
            return next_stats
    raise TimeoutError


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


@pytest.fixture(scope="module")
def generate_log_file():
    """Generate a log of size greater than 10 MiB for testing."""
    file.write_file(log_test_path, '')
    logcollector.add_log_data(log_test_path, metadata[0]['log_line'], size_kib=10240)
    yield
    file.remove_file(log_test_path)


@pytest.fixture(scope="function")
def create_socket():
    """Create a UNIX named socket for testing."""
    # config = get_configuration['metadata']
    # Check if the socket exists and unlink it
    if os.path.exists(metadata[0]['socket_path']):
        os.unlink(metadata[0]['socket_path'])

    if mode == "tcp":
        sock = socket(AF_UNIX, SOCK_STREAM)
        sock.bind(metadata[0]['socket_path'])
        sock.listen()
    else:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.bind(metadata[0]['socket_path'])
    yield
    sock.shutdown(SHUT_RDWR)
    sock.close()
    os.unlink(metadata[0]['socket_path'])


# @pytest.mark.parametrize('batch', lines_batch)
def test_location_custom_sockets(get_local_internal_options, configure_local_internal_options,
                                 get_configuration, configure_environment, generate_log_file,
                                 create_socket, restart_logcollector):
    """Check if the "location" option used with custom sockets is working correctly.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration for testing.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        generate_log_file (fixture): Generate a log file for testing.
        batch (fixture): Line batches to be added to the test log
        create_socket (fixture): Create a UNIX named socket for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.
    """
    config = get_configuration['metadata']
    global mode

    # Ensure that the log file is being analyzed
    callback_message = logcollector.callback_analyzing_file(file=config['location'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Add one line of data to force logcollector to connect to the socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the logcollector is connected to the socket
    callback_message = logcollector.callback_socket_connected(socket_name=config['socket_name'],
                                                              socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    stats = get_logcollector_data_sending_stats(config['location'], config['socket_name'])
    global_drops = int(stats['global_drops'])
    interval_drops = int(stats['interval_drops'])

    # Add batches of lines to log
    with open(config['location'], 'a') as f:
        for _ in range(0, config['lines_batch']):
            f.write(f"{config['log_line']}\n")

    stats = get_next_stats(stats, config['location'], config['socket_name'])
    global_drops += int(stats['global_drops'])
    interval_drops += int(stats['interval_drops'])

    print(config['lines_batch'])
    print(f"g_events: {stats['global_events']}, g_drops: {stats['global_drops']} ({stats['global_end_seconds']})")
    print(
        f"i_events: {stats['interval_events']}, i_drops: {stats['interval_drops']} ({stats['interval_end_seconds']})\n")

    # Obtain next statistics in case dropped events appear during the next interval
    stats = get_next_stats(stats, config['location'], config['socket_name'])
    global_drops += int(stats['global_drops'])
    interval_drops += int(stats['interval_drops'])

    print(f"g_events: {stats['global_events']}, g_drops: {stats['global_drops']} ({stats['global_end_seconds']})")
    print(f"i_events: {stats['interval_events']}, i_drops: {stats['interval_drops']} ({stats['interval_end_seconds']})")

    assert global_drops == interval_drops == 0, "Event drops have been detected."

    # mode = "udp"
    # sleep(600)
