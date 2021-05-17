# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from os import path, unlink
from socket import AF_UNIX, SHUT_RDWR, SOCK_STREAM, SOCK_DGRAM, socket
from tempfile import gettempdir

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.logcollector import (GENERIC_CALLBACK_ERROR_COMMAND_MONITORING, callback_analyzing_file,
                                        callback_socket_connected, callback_socket_offline,
                                        get_next_stats, get_data_sending_stats)
from wazuh_testing.tools import LOG_FILE_PATH, file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=1)]

# Configuration
DAEMON_NAME = "wazuh-logcollector"
test_data_path = path.join(path.dirname(path.realpath(__file__)), 'data')
configurations_path = path.join(test_data_path, 'wazuh_location_custom_sockets_conf.yaml')
temp_dir = gettempdir()
log_test_path = path.join(temp_dir, 'wazuh-testing', 'test.log')
test_socket = None

local_internal_options = {
    'logcollector.debug': 2,
    'logcollector.state_interval': 5,
    'logcollector.queue_size': 2048,
    'monitord.rotate_log': 0
}

# Batch sizes of events to add to the log file
batch_size = [5, 10, 50, 100, 500, 1000, 5000, 10000]

parameters = [
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
     'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'tcp'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
     'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'udp'}
]

metadata = [
    {'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket', 'mode': 'tcp',
     'socket_path': '/var/run/custom.sock', 'log_line': "Jan  1 00:00:00 localhost test[0]: log line"},
    {'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket', 'mode': 'udp',
     'socket_path': '/var/run/custom.sock', 'log_line': "Jan  1 00:00:00 localhost test[0]: log line"},
]

file_structure = [
    {
        'folder_path': path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.log'],
        'content': f"{metadata[0]['log_line']}",
        'size_kib': 10240
    }
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"target_{x['socket_name']}_mode_{x['mode']}" for x in metadata]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


@pytest.fixture(scope='function')
def restart_logcollector(get_configuration, request):
    """Reset log file and start a new monitor."""
    control_service('stop', daemon=DAEMON_NAME)
    file.truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon=DAEMON_NAME)


@pytest.fixture(scope="function")
def create_socket(get_configuration):
    """Create a UNIX named socket for testing."""
    config = get_configuration['metadata']
    global test_socket
    # Check if the socket exists and unlink it
    if path.exists(config['socket_path']):
        unlink(config['socket_path'])

    if config['mode'] == "tcp":
        test_socket = socket(AF_UNIX, SOCK_STREAM)
        test_socket.bind(config['socket_path'])
        test_socket.listen()
    else:
        test_socket = socket(AF_UNIX, SOCK_DGRAM)
        test_socket.bind(config['socket_path'])
    yield
    try:
        test_socket.shutdown(SHUT_RDWR)
        test_socket.close()
    except OSError:
        # The socket is already closed
        pass
    finally:
        if path.exists(config['socket_path']):
            unlink(config['socket_path'])


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.mark.parametrize("batch", batch_size, ids=[f"batch_{x}" for x in batch_size])
def test_location_custom_sockets(get_local_internal_options, configure_local_internal_options,
                                 get_configuration, configure_environment, create_file_structure_module,
                                 batch, create_socket, restart_logcollector):
    """Check if the "location" option used with custom sockets is working correctly.

    To do this, a UNIX "named socket" is created and added to the configuration
    through the "socket" section and the "target" option of the "localfile" section.
    Then, event batches of increasing size are added to the log and, at the same time,
    it is checked by analyzing the "wazuh-logcollector.state" file to see if these events are dropped.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration for testing.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        create_file_structure_module (fixture): Module scope version of create_file_structure.
        batch (fixture): Event batches to be added to the test log file.
        create_socket (fixture): Create a UNIX named socket for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.
    """
    config = get_configuration['metadata']

    # Ensure that the log file is being analyzed
    callback_message = callback_analyzing_file(file=config['location'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Add one event to force logcollector to connect to the socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the logcollector is connected to the socket
    callback_message = callback_socket_connected(socket_name=config['socket_name'],
                                                 socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # This way we make sure to get the statistics right at the beginning of an interval
    stats = get_data_sending_stats(log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    next_stats = get_next_stats(current_stats=stats,
                                log_path=config['location'],
                                socket_name=config['socket_name'],
                                state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops = int(next_stats[0]['interval_drops'])

    # Add batches of events to log file and check if drops
    with open(config['location'], 'a') as f:
        for _ in range(0, batch):
            f.write(f"{config['log_line']}\n")

    next_stats = get_next_stats(current_stats=next_stats[0],
                                log_path=config['location'],
                                socket_name=config['socket_name'],
                                state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # Obtain next statistics in case dropped events appear during the next interval
    next_stats = get_next_stats(current_stats=next_stats[0],
                                log_path=config['location'],
                                socket_name=config['socket_name'],
                                state_interval=local_internal_options['logcollector.state_interval'])
    global_drops = int(next_stats[0]['global_drops'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # Event drops should not occur with batches smaller than the value of "logcollector.queue_size".
    if batch > local_internal_options['logcollector.queue_size']:
        with pytest.raises(AssertionError):
            assert global_drops == interval_drops == 0, f"Event drops have been detected in batch {batch}."
    else:
        assert global_drops == interval_drops == 0, f"Event drops have been detected in batch {batch}."


@pytest.mark.parametrize("batch", batch_size, ids=[f"batch_{x}" for x in batch_size])
def test_location_custom_sockets_offline(get_local_internal_options, configure_local_internal_options,
                                         get_configuration, configure_environment, create_file_structure_module,
                                         batch, create_socket, restart_logcollector):
    """Verify that event drops occur when the socket to which they are sent becomes unavailable.

    To do this logcollector is configured to forward events to a socket, and when the connection
    has been established one event is written to the log file to force logcollector to connect
    to the socket, then the socket is closed and batch of events is written to the log file,
    in which case the event drops should be detected.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration for testing.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        create_file_structure_module (fixture): Module scope version of create_file_structure.
        batch (fixture): Event batches to be added to the test log file.
        create_socket (fixture): Create a UNIX named socket for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.
    """
    config = get_configuration['metadata']
    global test_socket

    # Ensure that the log file is being analyzed
    callback_message = callback_analyzing_file(file=config['location'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Add one event to force logcollector to connect to the socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the logcollector is connected to the socket
    callback_message = callback_socket_connected(socket_name=config['socket_name'],
                                                 socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Close socket
    test_socket.shutdown(SHUT_RDWR)
    test_socket.close()

    # Add another event to verify that logcollector cannot connect to the already closed socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the socket is closed
    callback_message = callback_socket_offline(socket_name=config['socket_name'],
                                               socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # This way we make sure to get the statistics right at the beginning of an interval
    stats = get_data_sending_stats(log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    next_stats = get_next_stats(current_stats=stats,
                                log_path=config['location'],
                                socket_name=config['socket_name'],
                                state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops = int(next_stats[0]['interval_drops'])

    # Add batches of events to log file and check if drops
    with open(config['location'], 'a') as f:
        for _ in range(0, batch):
            f.write(f"{config['log_line']}\n")

    next_stats = get_next_stats(current_stats=next_stats[0],
                                log_path=config['location'],
                                socket_name=config['socket_name'],
                                state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # Obtain next statistics in case dropped events appear during the next interval
    next_stats = get_next_stats(current_stats=next_stats[0],
                                log_path=config['location'],
                                socket_name=config['socket_name'],
                                state_interval=local_internal_options['logcollector.state_interval'])
    global_drops = int(next_stats[0]['global_drops'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # The number of global events must be the same as
    # the batch size plus one (the event to verify the closure of the socket).
    assert global_drops == batch + 1, "The global drops reported do not match those caused by the test."
    assert interval_drops == batch, "The interval drops reported do not match those caused by the test."
